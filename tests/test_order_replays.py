"""Order retries against an isolated SQLite database, never a configured service."""
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, false, func, select
from sqlalchemy.orm import Session

from server.database import Base, Customer, Order, OrderItem, Product
from server.modules import orders


@pytest.fixture
def replay_client(tmp_path, monkeypatch):
    engine = create_engine("sqlite:///" + str(tmp_path / "orders.sqlite"), connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Customer(id=1, name="Buyer", email="buyer@example.invalid"))
        db.add(Customer(id=2, name="Other buyer", email="other@example.invalid"))
        db.add(Product(id=1, name="Item", sku="item", price=10))
        db.commit()
    state = {"hide_lookup": False, "defer_flush": False, "unrelated_failure": False}

    class AsyncDb:
        def __init__(self, db):
            self.db = db

        async def execute(self, stmt):
            if state["hide_lookup"] and stmt.column_descriptions[0].get("entity") is Order:
                state["hide_lookup"] = False
                return self.db.execute(stmt.where(false()))
            return self.db.execute(stmt)

        async def get(self, model, pk):
            return self.db.get(model, pk)

        def add(self, obj):
            self.db.add(obj)

        async def flush(self):
            if state["defer_flush"]:
                return
            if state["unrelated_failure"]:
                state["unrelated_failure"] = False
                self.db.add(Customer(id=1, name="Duplicate", email="duplicate@example.invalid"))
            self.db.flush()

    @asynccontextmanager
    async def get_db():
        with Session(engine, expire_on_commit=False) as db:
            try:
                yield AsyncDb(db)
                db.commit()
            except Exception:
                db.rollback()
                raise

    monkeypatch.setattr(orders, "get_db", get_db)
    monkeypatch.setattr(orders, "cfg", SimpleNamespace(drone_shop_internal_key=""))
    monkeypatch.setattr(orders, "tracer_fn", MagicMock())
    monkeypatch.setattr(orders, "push_log", MagicMock())
    monkeypatch.setattr(orders.business_metrics, "record_order_created", MagicMock())
    app = FastAPI()
    app.include_router(orders.router)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client, engine, state
    engine.dispose()


def payload():
    return {
        "customer_id": 1,
        "items": [{"product_id": 1, "quantity": 2, "unit_price": 10}],
        "source_system": "upstream",
        "source_order_id": "order-1",
        "idempotency_token": "00000000-0000-0000-0000-000000000001",
        "shipping_address": "Example address",
        "notes": "Example note",
    }


@pytest.mark.parametrize("race", ["replay", "flush", "commit"])
def test_same_request_returns_original_without_duplicate(replay_client, race):
    client, engine, state = replay_client
    first = client.post("/api/orders", json=payload())
    assert first.status_code == 200
    state["hide_lookup"] = race != "replay"
    state["defer_flush"] = race == "commit"
    second = client.post("/api/orders", json=payload())
    assert second.status_code == 200, second.text
    assert second.json() == first.json()
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Order)) == 1
        assert db.scalar(select(func.count()).select_from(OrderItem)) == 1
    assert orders.business_metrics.record_order_created.call_count == 1


@pytest.mark.parametrize("field,value", [
    ("total", 123), ("customer_id", 2), ("notes", "Changed"), ("shipping_address", "Changed"),
    ("items", [{"product_id": 1, "quantity": 3, "unit_price": 10}]),
    ("idempotency_token", "00000000-0000-0000-0000-000000000002"),
])
@pytest.mark.parametrize("race", [False, True])
def test_changed_request_conflicts(replay_client, field, value, race):
    client, engine, state = replay_client
    first = client.post("/api/orders", json=payload())
    assert first.status_code == 200
    changed = payload()
    changed[field] = value
    state["hide_lookup"] = race
    response = client.post("/api/orders", json=changed)
    assert response.status_code == 409, response.text
    assert "source reference" in response.json()["detail"].lower()
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Order)) == 1


def test_replay_uses_original_total_after_catalog_price_changes(replay_client):
    client, engine, _ = replay_client
    first = client.post("/api/orders", json=payload())
    with Session(engine) as db:
        db.get(Product, 1).price = 20
        db.commit()
    response = client.post("/api/orders", json=payload())
    assert response.status_code == 200
    assert response.json() == first.json()


def test_source_reference_is_scoped_by_source_and_manual_orders_stay_distinct(replay_client):
    client, engine, _ = replay_client
    first = client.post("/api/orders", json=payload())
    other = payload()
    other["source_system"] = "another-upstream"
    second = client.post("/api/orders", json=other)
    manual = {"customer_id": 1, "items": payload()["items"]}
    third = client.post("/api/orders", json=manual)
    fourth = client.post("/api/orders", json=manual)
    assert all(r.status_code == 200 for r in [first, second, third, fourth])
    assert len({r.json()["order_id"] for r in [first, second, third, fourth]}) == 4


@pytest.mark.parametrize("source_payload", [None, "{}"])
def test_legacy_order_without_request_snapshot_conflicts(replay_client, source_payload):
    client, engine, _ = replay_client
    with Session(engine) as db:
        db.add(Order(customer_id=1, total=20, source_system="upstream",
                     source_order_id="order-1", source_payload=source_payload))
        db.commit()
    assert client.post("/api/orders", json=payload()).status_code == 409


def test_unrelated_integrity_failure_rolls_back_and_does_not_replay(replay_client):
    client, engine, state = replay_client
    state["unrelated_failure"] = True
    assert client.post("/api/orders", json=payload()).status_code == 500
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Order)) == 0
        assert db.scalar(select(func.count()).select_from(OrderItem)) == 0
    orders.business_metrics.record_order_created.assert_not_called()


def test_optional_token_default_source_and_fractional_price(replay_client):
    client, engine, _ = replay_client
    request = payload()
    request.pop("idempotency_token")
    request.pop("source_system")
    request["items"][0]["quantity"] = 3
    with Session(engine) as db:
        db.get(Product, 1).price = 0.1
        db.commit()
    first = client.post("/api/orders", json=request)
    second = client.post("/api/orders", json=request)
    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    with Session(engine) as db:
        order = db.scalar(select(Order))
        assert order.source_system == "enterprise-crm"
        assert order.total == pytest.approx(0.3)
