"""Behavioral contract for the local no-mistakes CI gate runner and config."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local_ci_gate.py"
CONFIG = ROOT / ".no-mistakes.yaml"


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def load_gate_module():
    assert SCRIPT.is_file(), f"Missing runner script: {SCRIPT}"
    spec = importlib.util.spec_from_file_location("local_ci_gate", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_list_exposes_all_required_gate_checks_without_failure_masking() -> None:
    result = invoke("--list")
    assert result.returncode == 0, result.stderr
    jobs = json.loads(result.stdout)

    expected_jobs = {
        "unit-tests",
        "smoke-tests",
        "python-sast",
        "dependency-audit",
        "secret-scan",
        "mkdocs-build",
        "container-scan",
    }
    assert expected_jobs <= set(jobs)

    all_commands = [
        cmd
        for row in jobs.values()
        for cmd in row["commands"]
    ]
    assert all_commands

    for cmd in all_commands:
        joined = " ".join(cmd)
        assert "||" not in joined
        assert cmd[:2] not in (["sh", "-c"], ["bash", "-c"], ["zsh", "-c"])

    assert any(
        "pytest" in cmd and "tests/test_health.py" in cmd and "tests/test_observability_frontend.py" in cmd
        for cmd in jobs["smoke-tests"]["commands"]
    )
    assert any(
        "pytest" in cmd and "tests/test_health.py" not in cmd
        for cmd in jobs["unit-tests"]["commands"]
    )
    assert any(
        cmd[:4] == ["bandit", "-q", "-r", "server"]
        for cmd in jobs["python-sast"]["commands"]
    )
    assert any(
        cmd[0] == "ruff" and "check" in cmd and "S" in cmd and "server" in cmd
        for cmd in jobs["python-sast"]["commands"]
    )
    assert ["pip-audit", "-r", "requirements.txt", "--strict"] in jobs["dependency-audit"]["commands"]
    assert any(
        cmd[:3] == ["mkdocs", "build", "--strict"] and "--site-dir" in cmd
        for cmd in jobs["mkdocs-build"]["commands"]
    )
    assert any(
        cmd[0] == "gitleaks" and "--redact" in cmd
        for cmd in jobs["secret-scan"]["commands"]
    )
    assert any(
        cmd[:2] == ["trivy", "config"] and "--exit-code" in cmd and "1" in cmd and "Dockerfile" in cmd
        for cmd in jobs["container-scan"]["commands"]
    )


def test_unknown_job_exits_nonzero_without_writing_receipt(tmp_path: Path) -> None:
    assert SCRIPT.is_file(), f"Missing runner script: {SCRIPT}"
    receipt = tmp_path / "receipt.json"
    result = invoke("--job", "nonexistent-job", "--receipt", str(receipt))
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
    assert not receipt.exists()


def test_run_commands_retains_exit_codes_strips_cloud_env_and_denies_network(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_gate_module()
    monkeypatch.setenv("OCI_TENANCY_Probe", "sensitive-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "sensitive-aws")

    env_dump = tmp_path / "env.json"
    commands = [
        [sys.executable, "-c", "raise SystemExit(7)"],
        [
            sys.executable,
            "-c",
            "import json, os; from pathlib import Path; "
            f"Path({str(env_dump)!r}).write_text(json.dumps({{"
            "'has_oci': 'OCI_TENANCY_Probe' in os.environ, "
            "'has_aws': 'AWS_SECRET_ACCESS_KEY' in os.environ, "
            "'oci_cfg': os.environ.get('OCI_CONFIG_FILE')"
            "}))",
        ],
        [sys.executable, "-c", "import socket; s = socket.socket(); s.bind(('', 0))"],
        ["definitely-missing-local-ci-binary-xyz"],
    ]

    log_dir = tmp_path / "logs"
    results = module.run_commands(commands, log_dir, isolate_network=True)
    assert [row["exit_code"] for row in results] == [7, 0, 1, 127]

    observed_env = json.loads(env_dump.read_text())
    assert observed_env == {
        "has_oci": False,
        "has_aws": False,
        "oci_cfg": "/dev/null",
    }
    for row in results:
        mode = stat.S_IMODE((log_dir / row["log"]).stat().st_mode)
        assert mode == 0o600


def test_cli_writes_private_receipt_and_propagates_pass_and_fail(
    tmp_path: Path, monkeypatch
) -> None:
    pass_receipt = tmp_path / "pass-receipt.json"
    passed = invoke("--job", "smoke-tests", "--receipt", str(pass_receipt))
    assert passed.returncode == 0, passed.stderr
    assert stat.S_IMODE(pass_receipt.stat().st_mode) == 0o600

    pass_data = json.loads(pass_receipt.read_text())
    assert pass_data["status"] == "passed"
    assert pass_data["provider_verified"] is False
    assert pass_data["release_accepted"] is False
    assert pass_data["jobs"]["smoke-tests"]["status"] == "passed"
    assert pass_data["excluded_workflow_checks"]
    assert all(
        item["status"] != "passed"
        for item in pass_data["excluded_workflow_checks"].values()
    )

    module = load_gate_module()
    fail_receipt = tmp_path / "fail-receipt.json"
    monkeypatch.setitem(
        module.JOBS,
        "synthetic-fail",
        module.JobSpec(
            commands=(([sys.executable, "-c", "raise SystemExit(3)"]),),
            network="deny",
            workflow="test:synthetic",
        ),
    )
    code = module.main(["--job", "synthetic-fail", "--receipt", str(fail_receipt)])
    assert code == 1
    fail_data = json.loads(fail_receipt.read_text())
    assert fail_data["status"] == "failed"
    assert fail_data["jobs"]["synthetic-fail"]["status"] == "failed"
    assert fail_data["jobs"]["synthetic-fail"]["commands"][0]["exit_code"] == 3


def test_no_mistakes_config_matches_strict_pilot_schema() -> None:
    assert CONFIG.is_file(), f"Missing config: {CONFIG}"
    config = yaml.safe_load(CONFIG.read_text())
    assert set(config.keys()) == {"commands", "auto_fix"}
    assert set(config["commands"].keys()) == {"test", "lint"}
    assert config["commands"]["test"] == "python3.11 scripts/local_ci_gate.py"
    assert config["commands"]["lint"].startswith("python3.11 scripts/local_ci_gate.py --job ")
    assert "||" not in config["commands"]["test"]
    assert "||" not in config["commands"]["lint"]
    assert config["auto_fix"] == {"review": 0, "test": 0, "lint": 0}


def test_private_gate_directories_are_gitignored() -> None:
    targets = [
        ".gate/local-ci/receipt.json",
        ".gate/venv/pyvenv.cfg",
        ".cache/local-ci/receipt.json",
    ]
    for target in targets:
        result = subprocess.run(
            ["git", "-c", "core.excludesfile=/dev/null", "check-ignore", "-v", target],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"{target} is not ignored by repo .gitignore"
        assert result.stdout.startswith(".gitignore:"), result.stdout
