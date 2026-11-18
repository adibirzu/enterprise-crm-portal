"""The platform control-plane probe uses the explicit OCI_DEMO_* URL aliases."""

from __future__ import annotations

import importlib

import pytest

NAMES = (
    "OCI_DEMO_BACKEND_URL",
    "PLATFORM_BACKEND_URL",
    "OCI_DEMO_CONTROL_PLANE_URL",
    "CONTROL_PLANE_URL",
    "DNS_DOMAIN",
)


@pytest.fixture(autouse=True)
def _restore_modules(monkeypatch: pytest.MonkeyPatch):
    yield
    monkeypatch.undo()
    import server.config
    import server.modules.integrations

    importlib.reload(server.config)
    importlib.reload(server.modules.integrations)


def _control_plane(monkeypatch: pytest.MonkeyPatch, **values: str) -> dict:
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    import server.config as config
    import server.modules.integrations as integrations

    importlib.reload(config)
    importlib.reload(integrations)
    return next(
        item
        for item in integrations._configured_dependencies()
        if item["name"] == "platform-control-plane"
    )


@pytest.mark.portability
def test_oci_demo_backend_alias_is_probed_first(monkeypatch: pytest.MonkeyPatch) -> None:
    item = _control_plane(
        monkeypatch,
        OCI_DEMO_BACKEND_URL="https://backend.tenant-a.example.invalid",
        PLATFORM_BACKEND_URL="https://backend.generic.example.invalid",
    )
    assert item["probe_url"] == "https://backend.tenant-a.example.invalid"


@pytest.mark.portability
def test_control_plane_alias_is_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    item = _control_plane(
        monkeypatch,
        OCI_DEMO_CONTROL_PLANE_URL="https://cp.tenant-a.example.invalid",
        CONTROL_PLANE_URL="https://cp.generic.example.invalid",
    )
    assert item["probe_url"] == "https://cp.tenant-a.example.invalid"


@pytest.mark.portability
def test_dns_domain_is_the_last_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    item = _control_plane(monkeypatch, DNS_DOMAIN="tenant-a.example.invalid")
    assert item["probe_url"] == "https://cp.tenant-a.example.invalid"
