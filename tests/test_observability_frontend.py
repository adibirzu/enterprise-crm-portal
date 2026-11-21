from __future__ import annotations

import json
import shutil
import subprocess

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from server.modules.observability_frontend import router

FRONTEND_ENDPOINT = "/api/observability/frontend"
OBSERVABILITY_SCRIPT = "/static/js/observability.js"

BROWSER_HARNESS = """
const vm = require('node:vm');
const fs = require('node:fs');
const [pathname, transport] = process.argv.slice(1);
const requests = [];
const listeners = {};
const fetch = async (url, options) => {
    requests.push([url, JSON.parse(options.body)]);
};
const browser = {
    Blob: class {
        constructor([body]) { this.body = body; }
    },
    crypto: { randomUUID: () => 'test-view' },
    document: { addEventListener() {}, body: {} },
    localStorage: { getItem: () => 'browser-correlation-id' },
    location: { pathname },
    MutationObserver: class { observe() {} },
    navigator: transport === 'beacon' ? {
        sendBeacon: (url, blob) => requests.push([url, JSON.parse(blob.body)]),
    } : {},
    performance: { getEntriesByType: () => [{ responseStart: 25 }] },
    window: { fetch, addEventListener: (name, handler) => { listeners[name] = handler; } },
};
vm.runInNewContext(fs.readFileSync(0, 'utf8'), browser);
listeners.error?.({ message: 'Example error' });
listeners.unhandledrejection?.({ reason: 'Example rejection' });
process.stdout.write(JSON.stringify(requests));
"""


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_frontend_observability_accepts_json_payload() -> None:
    client = _client()

    response = client.post(
        "/api/observability/frontend",
        json={
            "type": "navigation",
            "page": "/products",
            "session_id": "session-1",
            "view_id": "view-1",
            "ts": 1,
            "payload": {},
        },
    )

    assert response.status_code == 204


def test_frontend_observability_accepts_sendbeacon_text_payload() -> None:
    client = _client()

    response = client.post(
        "/api/observability/frontend",
        content='{"type":"navigation","page":"/products","session_id":"session-1","view_id":"view-1","ts":1,"payload":{}}',
        headers={"Content-Type": "text/plain;charset=UTF-8"},
    )

    assert response.status_code == 204


def test_frontend_observability_drops_invalid_payload_without_422() -> None:
    client = _client()

    response = client.post(
        "/api/observability/frontend",
        content="not-json",
        headers={"Content-Type": "text/plain;charset=UTF-8"},
    )

    assert response.status_code == 204


@pytest.mark.parametrize("transport", ["beacon", "fetch"])
@pytest.mark.parametrize(("page", "signed_in"), [("/login", False), ("/products", True)])
def test_frontend_telemetry_follows_page_session(
    crm_client: TestClient, monkeypatch: pytest.MonkeyPatch,
    page: str, signed_in: bool, transport: str,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to execute the browser telemetry script")

    from server.modules import auth

    monkeypatch.setattr(
        auth, "get_current_user",
        lambda request: {"user_id": 1, "username": "test-user", "role": "viewer"}
        if request.cookies.get("session_id") == "test-session" else None,
    )
    if signed_in:
        crm_client.cookies.set("session_id", "test-session")

    response = crm_client.get(page)
    assert response.status_code == 200
    requests = []
    if f'src="{OBSERVABILITY_SCRIPT}"' in response.text:
        script = crm_client.get(OBSERVABILITY_SCRIPT)
        assert script.status_code == 200
        result = subprocess.run(
            [node, "-e", BROWSER_HARNESS, page, transport],
            input=script.text, text=True, capture_output=True, check=True, timeout=5,
        )
        requests = json.loads(result.stdout)

    if signed_in:
        assert {body["type"] for _, body in requests} == {
            "web_vital", "js_error", "promise_rejection",
        }
        for url, body in requests:
            assert url == FRONTEND_ENDPOINT
            assert body["page"] == page
            assert crm_client.post(url, json=body).status_code == 204
    else:
        assert requests == []


def test_frontend_observability_requires_authentication(crm_client: TestClient) -> None:
    response = crm_client.post(
        FRONTEND_ENDPOINT, json={"type": "navigation", "page": "/login"},
    )

    assert response.status_code == 401
