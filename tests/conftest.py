"""Add project root to sys.path so server module is importable."""
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def crm_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from server import config

    with monkeypatch.context() as settings:
        settings.setattr(config, "cfg", replace(config.cfg, app_env="development"))
        from server.main import app

    # Exercise the app without starting its database bootstrap or sync loop.
    return TestClient(app)
