from contextlib import asynccontextmanager, nullcontext
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def customer_db(monkeypatch):
    from server.modules import customers

    row = SimpleNamespace(_mapping={"id": 1, "name": "Example Customer"})
    result = Mock()
    result.fetchall.return_value = [row]
    result.fetchone.return_value = row
    execute = AsyncMock(return_value=result)

    @asynccontextmanager
    async def get_db():
        yield SimpleNamespace(execute=execute)

    monkeypatch.setattr(customers, "get_db", get_db)
    return execute


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/customers"),
        ("GET", "/api/customers/1"),
        ("POST", "/api/customers"),
        ("PUT", "/api/customers/1"),
        ("GET", "/api/customers/"),
    ],
)
def test_customer_endpoints_require_session(crm_client, customer_db, method, path):
    response = crm_client.request(method, path, json={"name": "Example Customer"})
    assert response.status_code == 401
    customer_db.assert_not_awaited()


def test_signed_in_customer_list_reaches_handler(crm_client, customer_db, monkeypatch):
    from server.modules import auth

    def lookup(request):
        if request.cookies.get("session_id") == "example-session":
            return {"user_id": 1, "username": "example", "role": "user"}

    monkeypatch.setattr(auth, "get_current_user", lookup)
    crm_client.cookies.set("session_id", "example-session")
    response = crm_client.get("/api/customers")

    assert response.status_code == 200
    assert response.json()["customers"] == [{"id": 1, "name": "Example Customer"}]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/orders"),
        ("GET", "/api/orders/1"),
        ("GET", "/api/orders/backlog"),
        ("GET", "/api/orders/security/summary"),
        ("POST", "/api/orders/sync"),
        ("PATCH", "/api/orders/1/status"),
        ("GET", "/api/invoices"),
        ("GET", "/api/invoices/1"),
        ("GET", "/api/invoices/1/pdf"),
        ("POST", "/api/invoices/1/pay"),
        ("GET", "/api/tickets"),
        ("POST", "/api/tickets"),
        ("GET", "/api/tickets/redirect"),
        ("GET", "/api/integrations/drone-shop/order-history"),
        ("GET", "/api/integrations/mushop/order-history"),
        ("GET", "/api/integrations/console/connections"),
        ("GET", "/api/integrations/status"),
        ("GET", "/api/observability/360"),
        ("GET", "/api/observability/360/db-health"),
        ("GET", "/api/observability/360/security"),
    ],
)
def test_related_data_endpoints_require_session(crm_client, monkeypatch, method, path):
    from server.modules import integrations, invoices, observability_dashboard, orders, tickets

    unavailable = Mock(side_effect=RuntimeError("External dependencies are disabled"))
    for module in (invoices, orders, tickets):
        monkeypatch.setattr(module, "get_db", unavailable)
    for name in ("list_backlog_orders", "order_security_summary", "sync_external_orders"):
        monkeypatch.setattr(orders, name, unavailable)
    for name in ("_app_health_summary", "_db_health_summary", "_security_summary"):
        monkeypatch.setattr(observability_dashboard, name, unavailable)
    for name in ("_get_json", "_collect_dependency_status"):
        monkeypatch.setattr(integrations, name, unavailable)
    monkeypatch.setattr(integrations, "cfg", SimpleNamespace(control_plane_url=""))
    client = TestClient(crm_client.app, raise_server_exceptions=False)
    response = client.request(method, path, json={})

    assert response.status_code == 401
    unavailable.assert_not_called()


def test_integration_schema_remains_public(crm_client):
    response = crm_client.get("/api/integrations/schema")
    assert response.status_code == 200
    assert "/api/orders" in response.json()["paths"]


@pytest.mark.parametrize(
    ("key", "headers", "signed_in", "status"),
    [
        ("", {}, False, 401),
        ("example-key", {}, False, 401),
        ("example-key", {"X-Internal-Service-Key": "wrong-key"}, False, 401),
        ("example-key", {"X-Internal-Service-Key": "example-key"}, False, 200),
        ("example-key", {}, True, 200),
    ],
)
def test_order_creation_requires_session_or_service_key(
    crm_client, monkeypatch, key, headers, signed_in, status
):
    from server.modules import auth, orders

    monkeypatch.setattr(orders, "cfg", replace(orders.cfg, drone_shop_internal_key=key))
    monkeypatch.setattr(orders, "get_db", lambda: nullcontext())
    if signed_in:
        monkeypatch.setattr(auth, "get_current_user", lambda request: {"user_id": 1})
        crm_client.cookies.set("session_id", "example-session")
    response = crm_client.post("/api/orders", headers=headers, json={})
    assert response.status_code == status
