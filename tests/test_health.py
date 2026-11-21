"""Minimal health check test to satisfy pre-push hook."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


def test_config_loads():
    """Verify config module imports and instantiates."""
    from server.config import Config
    cfg = Config()
    assert cfg is not None


def test_favicon_is_wired_in_template_and_route() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    base_template = (repo_root / "server" / "templates" / "base.html").read_text()
    main_module = (repo_root / "server" / "main.py").read_text()

    assert 'rel="icon"' in base_template
    assert "/static/img/octo-icon.png" in base_template
    assert '"/favicon.ico"' in main_module
    assert "async def favicon()" in main_module


def test_api_health_matches_public_health(crm_client: TestClient) -> None:
    liveness = crm_client.get("/health")
    response = crm_client.get("/api/health")

    assert liveness.status_code == response.status_code == 200
    assert response.json() == liveness.json()
    assert response.json()["status"] == "ok"


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/api/products"), ("GET", "/api/healthcheck"), ("POST", "/api/health")],
)
def test_health_alias_does_not_open_protected_paths(
    crm_client: TestClient, method: str, path: str
) -> None:
    assert crm_client.request(method, path).status_code == 401
