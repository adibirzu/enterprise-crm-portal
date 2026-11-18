"""Oracle credentials must be URL-escaped in the generated SQLAlchemy URLs."""

from __future__ import annotations

import importlib

import pytest
from sqlalchemy.engine import make_url

CREDENTIALS = [
    ("app@user", "p@ss:w/rd#1%"),
    ("app user", "pass word+1"),
]


@pytest.fixture(autouse=True)
def _restore_modules(monkeypatch: pytest.MonkeyPatch):
    yield
    monkeypatch.undo()
    import server.config

    importlib.reload(server.config)


def _cfg(monkeypatch: pytest.MonkeyPatch, user: str, password: str):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("ORACLE_USER", user)
    monkeypatch.setenv("ORACLE_PASSWORD", password)
    monkeypatch.setenv("ORACLE_DSN", "crmdb_low")
    import server.config as module

    importlib.reload(module)
    return module.cfg


@pytest.mark.parametrize(("user", "password"), CREDENTIALS)
@pytest.mark.parametrize("attribute", ["database_url", "database_sync_url"])
def test_reserved_characters_in_credentials_round_trip(
    monkeypatch: pytest.MonkeyPatch, attribute: str, user: str, password: str
) -> None:
    url = make_url(getattr(_cfg(monkeypatch, user, password), attribute))

    assert url.username == user
    assert url.password == password
    assert url.host is None
    assert url.drivername.startswith("oracle+oracledb")
