import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_validates_and_exports_source_commit():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert re.search(r"(?m)^ARG SOURCE_COMMIT(?:=.*)?$", dockerfile)
    assert re.search(r"(?m)^ENV SOURCE_COMMIT=\$\{?SOURCE_COMMIT\}?", dockerfile)
    validation = next(line.removeprefix("RUN ") for line in dockerfile.splitlines()
                      if line.startswith("RUN ") and "SOURCE_COMMIT" in line)
    for commit, expected in [("a" * 40, 0), ("A" * 40, 0), ("", 1), ("g" * 40, 1), ("a" * 39, 1), ("a" * 39 + "\n", 1)]:
        result = subprocess.run(["sh", "-c", validation], env={"SOURCE_COMMIT": commit})
        assert (result.returncode == 0) == (expected == 0)


@pytest.mark.parametrize("path", ["/health", "/api/health"])
@pytest.mark.parametrize("commit,version", [("a" * 40, "example"), ("", "")])
def test_liveness_reports_identity_without_auth_or_io(crm_client, monkeypatch, path, commit, version):
    import server.main as main
    from server.config import Config

    monkeypatch.setenv("SOURCE_COMMIT", commit)
    monkeypatch.setenv("APP_VERSION", version)
    monkeypatch.setattr(main, "cfg", replace(Config(), app_name="example-service"))
    response = crm_client.get(path)
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "example-service", "build": {
        "source_commit": commit or "unknown", "version": version or "unknown",
    }}


@pytest.mark.parametrize("filename", ["deployment.yaml", "deployment-atp.yaml"])
def test_release_manifests_carry_identity_without_mutable_image(filename):
    deployment = next(yaml.safe_load_all((ROOT / "deploy/k8s" / filename).read_text()))
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    assert container["image"] == ""
    env = {entry["name"]: entry for entry in container["env"]}
    assert "SOURCE_COMMIT" not in env  # Preserve the value baked into the image.
    assert "SOURCE_COMMIT" in (ROOT / "deploy/k8s" / filename).read_text()
    assert "APP_VERSION" in env
