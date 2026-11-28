import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/standalone/deploy.sh"
K8S = ROOT / "deploy/k8s"
REPOSITORY = "registry.example.test/team/crm"
DIGEST = "sha256:" + "a" * 64
IMAGE = f"{REPOSITORY}@{DIGEST}"

FAKE_COMMAND = """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
if tool == "uname":
    assert args == ["-m"]
    print(os.environ["TEST_ARCH"])
    sys.exit(0)

with open(os.environ["TEST_COMMANDS"], "a") as log:
    print(json.dumps([tool, *args]), file=log)

if tool == "docker":
    if "--metadata-file" in args:
        metadata = {"containerimage.config.digest": "sha256:" + "b" * 64}
        if os.environ["TEST_DIGEST"]:
            metadata["containerimage.digest"] = os.environ["TEST_DIGEST"]
        Path(args[args.index("--metadata-file") + 1]).write_text(json.dumps(metadata))
elif tool == "kubectl":
    if args == ["apply", "-f", "-"]:
        with open(os.environ["TEST_RESOURCES"], "a") as resources:
            resources.write("---\\n" + sys.stdin.read())
else:
    sys.exit(f"Unexpected command: {tool}")
"""


@pytest.fixture
def deploy(tmp_path):
    command = tmp_path / "fake-command"
    command.write_text(FAKE_COMMAND)
    command.chmod(0o755)
    for executable in ("docker", "kubectl", "oci", "uname"):
        (tmp_path / executable).symlink_to(command)
    (tmp_path / "python3").symlink_to(sys.executable)
    wallet = tmp_path / "wallet"
    wallet.mkdir()
    commands = tmp_path / "commands.jsonl"
    resources = tmp_path / "resources.yaml"

    def run(**overrides):
        env = {
            "PATH": os.pathsep.join((str(tmp_path), os.defpath)),
            "DNS_DOMAIN": "example.test",
            "ORACLE_DSN": "example_low",
            "ORACLE_PASSWORD": "synthetic",
            "ORACLE_WALLET_DIR": str(wallet),
            "ORACLE_WALLET_PASSWORD": "synthetic",
            "APP_SECRET_KEY": "synthetic",
            "OCIR_REGION": "example-region",
            "OCIR_TENANCY": "example-team",
            "NAMESPACE": "example-crm",
            "TEST_ARCH": "x86_64",
            "TEST_DIGEST": DIGEST,
            "TEST_COMMANDS": str(commands),
            "TEST_RESOURCES": str(resources),
        }
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=ROOT,
            env=env | overrides,
            capture_output=True,
            text=True,
            timeout=15,
        )
        calls = [json.loads(line) for line in commands.read_text().splitlines()] if commands.exists() else []
        objects = (
            {obj["kind"]: obj for obj in yaml.safe_load_all(resources.read_text()) if obj}
            if resources.exists()
            else {}
        )
        return result, calls, objects

    return run


def test_prebuilt_image_deploys_the_supplied_digest(deploy):
    result, calls, objects = deploy(
        SKIP_BUILD="true", IMAGE_REF=IMAGE, OCIR_REGION="", OCIR_TENANCY="", TEST_ARCH="arm64"
    )

    assert result.returncode == 0, result.stderr
    assert all(call[0] == "kubectl" for call in calls)
    (container,) = objects["Deployment"]["spec"]["template"]["spec"]["containers"]
    assert container["image"] == IMAGE


@pytest.mark.parametrize(
    "image",
    ["", REPOSITORY, f"{REPOSITORY}:latest", f"{REPOSITORY}:v1", f"{REPOSITORY}@sha256:abcd",
     f"{REPOSITORY}:v1@{DIGEST}", f"{IMAGE}\nextra: value"],
)
def test_skip_build_rejects_references_without_a_valid_digest(deploy, image):
    result, calls, objects = deploy(SKIP_BUILD="true", IMAGE_REF=image)

    assert result.returncode != 0
    assert "IMAGE_REF" in result.stderr
    assert calls == []
    assert objects == {}


@pytest.mark.parametrize(
    ("arch", "platform", "expected_platform"),
    [("x86_64", "", "linux/amd64"), ("amd64", "", "linux/amd64"), ("arm64", "linux/arm64", "linux/arm64")],
)
def test_build_deploys_the_pushed_digest(deploy, arch, platform, expected_platform):
    result, calls, objects = deploy(TEST_ARCH=arch, IMAGE_PLATFORM=platform, IMAGE_TAG="example-release")

    assert result.returncode == 0, result.stderr
    repository = "example-region.ocir.io/example-team/enterprise-crm-portal"
    (container,) = objects["Deployment"]["spec"]["template"]["spec"]["containers"]
    assert container["image"] == f"{repository}@{DIGEST}"
    docker_calls = [call for call in calls if call[0] == "docker"]
    assert docker_calls
    assert all(not arg.endswith(":latest") for call in docker_calls for arg in call)
    assert any(
        "--push" in call and f"{repository}:example-release" in call
        and call[call.index("--platform") + 1] == expected_platform
        for call in docker_calls
    )


def test_build_on_non_amd64_requires_explicit_platform(deploy):
    result, calls, objects = deploy(TEST_ARCH="arm64")

    assert result.returncode != 0
    assert "IMAGE_PLATFORM" in result.stderr
    assert calls == []
    assert objects == {}


def test_build_rejects_latest_tag_before_running_docker(deploy):
    result, calls, objects = deploy(IMAGE_TAG="latest")

    assert result.returncode != 0
    assert "IMAGE_TAG" in result.stderr
    assert calls == []
    assert objects == {}


@pytest.mark.parametrize("digest", ["", "sha256:abcd"])
def test_unusable_push_digest_stops_before_cluster_changes(deploy, digest):
    result, calls, objects = deploy(TEST_DIGEST=digest)

    assert result.returncode != 0
    assert "digest" in result.stderr
    assert calls and all(call[0] == "docker" for call in calls)
    assert objects == {}


def test_standalone_workload_matches_hardening_and_preserves_atp_contract(deploy):
    result, calls, objects = deploy(SKIP_BUILD="true", IMAGE_REF=IMAGE)
    assert result.returncode == 0, result.stderr
    deployment = objects["Deployment"]
    pod = deployment["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    for manifest in ("deployment.yaml", "deployment-atp.yaml"):
        hardened = next(yaml.safe_load_all((K8S / manifest).read_text()))["spec"]["template"]["spec"]
        (hardened_container,) = hardened["containers"]
        assert pod.get("securityContext") == hardened["securityContext"]
        assert pod.get("automountServiceAccountToken") is hardened["automountServiceAccountToken"]
        assert container.get("securityContext") == hardened_container["securityContext"]
        assert pod["volumes"] == [
            {"name": "wallet", "secret": {"secretName": "crm-wallet"}}, *hardened["volumes"]
        ]
        assert container["volumeMounts"] == [
            {"name": "wallet", "mountPath": "/app/wallet", "readOnly": True},
            *hardened_container["volumeMounts"],
        ]
    assert deployment["metadata"]["namespace"] == "example-crm"
    assert deployment["spec"]["replicas"] == 1
    assert container["name"] == "crm"
    assert container["envFrom"] == [
        {"configMapRef": {"name": "crm-config"}},
        {"secretRef": {"name": "crm-secrets"}},
    ]
    assert objects["ConfigMap"]["data"]["ORACLE_DSN"] == "example_low"
    assert objects["ConfigMap"]["data"]["ORACLE_WALLET_DIR"] == "/app/wallet"
    assert any(call[:5] == ["kubectl", "create", "secret", "generic", "crm-wallet"] for call in calls)
    assert container["readinessProbe"] == {
        "httpGet": {"path": "/health", "port": 8080}, "initialDelaySeconds": 10, "periodSeconds": 10,
    }
    assert container["livenessProbe"] == {
        "httpGet": {"path": "/health", "port": 8080}, "initialDelaySeconds": 30, "periodSeconds": 30,
    }
    assert objects["Service"]["spec"]["type"] == "ClusterIP"


def test_build_passes_resolved_source_commit(deploy):
    result, calls, _ = deploy()
    assert result.returncode == 0, result.stderr
    build = next(call for call in calls if call[0] == "docker")
    expected = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    assert "--build-arg" in build
    assert build[build.index("--build-arg") + 1] == f"SOURCE_COMMIT={expected}"


def test_invalid_source_commit_stops_before_build(deploy):
    result, calls, objects = deploy(SOURCE_COMMIT="invalid")
    assert result.returncode != 0
    assert "SOURCE_COMMIT" in result.stderr
    assert calls == []
    assert objects == {}
