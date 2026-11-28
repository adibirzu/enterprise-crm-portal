"""Application imports with the database drivers shipped in its dependencies."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        ({"DATABASE_URL": "postgresql://user:pass@localhost:5432/crm"}, "postgresql"),
        ({"DATABASE_URL": "postgresql+asyncpg://user:pass@localhost:5432/crm"}, "postgresql"),
        ({"ORACLE_DSN": "example_low", "ORACLE_PASSWORD": "example"}, "oracle"),
        ({}, "unconfigured"),
    ],
    ids=["postgres", "postgres-async-url", "oracle", "unconfigured"],
)
def test_import_and_public_endpoints(settings, expected):
    script = '''
from fastapi.testclient import TestClient
from server import database, main
if expected == "unconfigured":
    assert database.engine is None and database.sync_engine is None
else:
    assert database.engine is not None and database.sync_engine is not None
    assert database.engine.dialect.name == expected
    assert database.sync_engine.dialect.name == expected
assert main._sync_engine is not None
client = TestClient(main.app)
for path in ("/health", "/api/health"):
    response = client.get(path)
    assert response.status_code == 200
    assert response.json()["build"]["source_commit"] == "a" * 40
assert client.get("/api/customers").status_code == 401
'''
    env = {"PATH": os.environ.get("PATH", ""), "SOURCE_COMMIT": "a" * 40, "APP_ENV": "development", **settings}
    result = subprocess.run(
        [sys.executable, "-c", f"expected = {expected!r}\n" + script],
        cwd=ROOT, env=env, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
