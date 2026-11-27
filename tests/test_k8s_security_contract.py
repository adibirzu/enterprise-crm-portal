import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
K8S = ROOT / "deploy/k8s"
IMAGE_REPOSITORY = "registry.example.invalid/team/crm"
IMAGE = f"{IMAGE_REPOSITORY}@sha256:{'a' * 64}"
VARIANTS = ("standard", "atp")


def render(variant, *image_args):
    readme = (ROOT / "README.md").read_text()
    _, marker, block = readme.partition("```bash crm-release-render\n")
    assert marker, "README must define the release renderer"
    renderer = block.split("```", 1)[0]
    return subprocess.run(
        ["bash", "-c", renderer + '\nrender_crm "$@"', "render_crm", variant, *image_args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("variant", VARIANTS)
def test_valid_digest_renders_a_hardened_workload(variant):
    result = render(variant, IMAGE)
    assert result.returncode == 0, result.stderr
    resources = list(yaml.safe_load_all(result.stdout))
    assert sorted(resource["kind"] for resource in resources) == ["Deployment", "Service"]
    deployment = next(resource for resource in resources if resource["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    assert container["name"] == "app"
    assert container["image"] == IMAGE

    user = [
        line.removeprefix("USER ").strip()
        for line in (ROOT / "Dockerfile").read_text().splitlines()
        if line.startswith("USER ")
    ][-1]
    uid, gid = map(int, user.split(":"))
    assert uid > 0 and gid > 0
    security = pod["securityContext"]
    assert security["runAsNonRoot"] is True
    for key, value in (("runAsUser", uid), ("runAsGroup", gid), ("fsGroup", gid)):
        assert type(security[key]) is int
        assert security[key] == value
    assert security["seccompProfile"] == {"type": "RuntimeDefault"}
    assert pod["automountServiceAccountToken"] is False
    security = container["securityContext"]
    assert security["capabilities"] == {"drop": ["ALL"]}
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert container["volumeMounts"] == [{"name": "tmp", "mountPath": "/tmp"}]
    assert pod["volumes"] == [{"name": "tmp", "emptyDir": {"sizeLimit": "256Mi"}}]

    startup = {
        "httpGet": {"path": "/health", "port": 8080},
        "initialDelaySeconds": 5,
        "periodSeconds": 5,
        "failureThreshold": 12,
    }
    liveness = {
        "httpGet": {"path": "/health", "port": 8080},
        "initialDelaySeconds": 15,
        "periodSeconds": 10,
    }
    readiness = {
        "httpGet": {"path": "/ready", "port": 8080},
        "initialDelaySeconds": 10,
        "periodSeconds": 5,
    }
    if variant == "standard":
        liveness["failureThreshold"] = readiness["failureThreshold"] = 3
    assert container["startupProbe"] == startup
    assert container["livenessProbe"] == liveness
    assert container["readinessProbe"] == readiness
    assert container["envFrom"] == [{"secretRef": {"name": "crm-portal-secrets", "optional": False}}]
    bindings = {
        env["name"]: env["valueFrom"] for env in container["env"] if "valueFrom" in env
    }
    expected_keys = (
        {
            "ATP_CONNECTION_NAME": "ATP_CONNECTION_NAME",
            "ATP_OCID": "ATP_OCID",
            "MUSHOP_CLOUDNATIVE_URL": "C28_MUSHOP_URL",
            "OCTO_DRONE_SHOP_URL": "OCTO_DRONE_SHOP_URL",
            "EXTERNAL_ORDERS_URL": "EXTERNAL_ORDERS_URL",
            "OCTO_APM_CLOUDNATIVE_URL": "C28_MUSHOP_URL",
            "CONTROL_PLANE_URL": "CONTROL_PLANE_URL",
            "PLATFORM_BACKEND_URL": "PLATFORM_BACKEND_URL",
            "APM_CONSOLE_URL": "APM_CONSOLE_URL",
            "OPSI_CONSOLE_URL": "OPSI_CONSOLE_URL",
            "DB_MANAGEMENT_CONSOLE_URL": "DB_MANAGEMENT_CONSOLE_URL",
            "LOG_ANALYTICS_CONSOLE_URL": "LOG_ANALYTICS_CONSOLE_URL",
        }
        if variant == "atp"
        else {}
    )
    assert bindings == {
        name: {"secretKeyRef": {"name": "crm-portal-secrets", "key": key, "optional": True}}
        for name, key in expected_keys.items()
    }


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize(
    "image_args",
    [
        (),
        ("",),
        (IMAGE_REPOSITORY,),
        (f"{IMAGE_REPOSITORY}:latest",),
        (f"{IMAGE_REPOSITORY}:v1.2.3",),
        (f"{IMAGE_REPOSITORY}@sha256:abcd",),
        (f"{IMAGE}\nextra: value",),
    ],
)
def test_invalid_release_image_emits_no_manifests(variant, image_args):
    result = render(variant, *image_args)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "approved image digest" in result.stderr


def test_committed_kustomization_requires_release_inputs():
    result = subprocess.run(
        ["kubectl", "kustomize", str(K8S)], capture_output=True, text=True, check=False
    )
    assert result.returncode != 0
    assert result.stdout == ""
    assert "release-workload.yaml" in result.stderr


@pytest.mark.parametrize("filename", ["deployment.yaml", "deployment-atp.yaml"])
def test_raw_workloads_have_no_deployable_image(filename):
    deployment = next(yaml.safe_load_all((K8S / filename).read_text()))
    (container,) = deployment["spec"]["template"]["spec"]["containers"]
    assert container["image"] == ""
