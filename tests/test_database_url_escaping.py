"""Oracle credentials must be URL-escaped in the generated SQLAlchemy URLs."""

from __future__ import annotations

import importlib

import pytest
from sqlalchemy.engine import make_url

USER = "app@user"
PASSWORD = "p@ss:w/rd#1%"


@pytest.fixture(autouse=True)
def _restore_modules(monkeypatch: pytest.MonkeyPatch):
    yield
    monkeypatch.undo()
    import server.config

    importlib.reload(server.config)


def _cfg(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ORACLE_USER", USER)
    monkeypatch.setenv("ORACLE_PASSWORD", PASSWORD)
    monkeypatch.setenv("ORACLE_DSN", "crmdb_low")
    import server.config as module

    importlib.reload(module)
    return module.cfg


@pytest.mark.parametrize("attribute", ["database_url", "database_sync_url"])
def test_reserved_characters_in_credentials_round_trip(
    monkeypatch: pytest.MonkeyPatch, attribute: str
) -> None:
    url = make_url(getattr(_cfg(monkeypatch), attribute))

    assert url.username == USER
    assert url.password == PASSWORD
    assert url.host is None
    assert url.drivername.startswith("oracle+oracledb")
