"""Behavioral contract for the local no-mistakes CI gate runner and config."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local_ci_gate.py"
CONFIG = ROOT / ".no-mistakes.yaml"
OFFLINE_JOBS = (
    "unit-tests",
    "smoke-tests",
    "python-sast",
    "secret-scan",
    "mkdocs-build",
    "container-scan",
)


def invoke(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
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


def _write_executable(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o755)
    return path


def _require_outer_socket_permission() -> None:
    """The two live exception tests need an unrestricted parent process."""
    with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
        with socket.socket(socket.AF_UNIX) as probe:
            try:
                probe.bind(str(Path(directory) / "probe.sock"))
            except PermissionError:
                pytest.skip("Run this live Seatbelt probe outside the offline aggregate")


def test_list_exposes_all_required_gate_checks_without_failure_masking() -> None:
    result = invoke("--list")
    assert result.returncode == 0, result.stderr
    jobs = json.loads(result.stdout)

    expected_jobs = {*OFFLINE_JOBS, "dependency-audit"}
    assert expected_jobs <= set(jobs)

    for job_name in OFFLINE_JOBS:
        assert jobs[job_name]["available"] is True
        assert jobs[job_name]["network"] == "deny"

    assert jobs["dependency-audit"]["available"] is False
    assert jobs["dependency-audit"]["network"] == "deny"
    assert jobs["dependency-audit"]["reason"]

    online_list = invoke("--list", "--allow-online")
    assert online_list.returncode == 0, online_list.stderr
    online_jobs = json.loads(online_list.stdout)
    assert online_jobs["dependency-audit"]["available"] is True
    assert (
        online_jobs["dependency-audit"]["network"]
        == "outbound-permitted (inbound/bind denied)"
    )
    for job_name in OFFLINE_JOBS:
        assert online_jobs[job_name]["network"] == "deny"

    all_commands = [cmd for row in jobs.values() for cmd in row["commands"]]
    assert all_commands

    for cmd in all_commands:
        joined = " ".join(cmd)
        assert "||" not in joined
        assert cmd[:2] not in (["sh", "-c"], ["bash", "-c"], ["zsh", "-c"])

    assert any(
        "pytest" in cmd
        and "tests/test_health.py" in cmd
        and "tests/test_observability_frontend.py" in cmd
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
    assert jobs["dependency-audit"]["commands"][0][:4] == [
        "pip-audit", "-r", "requirements.txt", "--strict"
    ]
    assert jobs["node-audit"]["workflow"] == "security-gates.yml:node-audit"
    assert jobs["node-audit"]["available"] is False
    assert "lockfile" in online_jobs["node-audit"]["reason"]
    assert jobs["terraform-lint"]["commands"] == [
        ["terraform", "-chdir=deploy/terraform", "fmt", "-check", "-recursive"],
        ["tflint", "--init"],
        ["tflint", "--chdir=deploy/terraform", "--recursive"],
    ]
    semgrep = next(cmd for cmd in jobs["python-sast"]["commands"] if cmd[0] == "semgrep")
    assert {Path(arg).name for arg in semgrep if arg.startswith(".gate/")} == {
        "owasp-top-ten.yml", "python.yml", "fastapi.yml"
    }
    assert any(
        cmd[:3] == ["mkdocs", "build", "--strict"] and "--site-dir" in cmd
        for cmd in jobs["mkdocs-build"]["commands"]
    )
    assert jobs["secret-scan"]["commands"][0][-1] == "--added-line-scan"
    assert any(
        cmd[:2] == ["trivy", "config"]
        and "--exit-code" in cmd
        and "1" in cmd
        and cmd[-1] == "."
        for cmd in jobs["container-scan"]["commands"]
    )


def test_unknown_job_exits_nonzero_without_writing_receipt(tmp_path: Path) -> None:
    assert SCRIPT.is_file(), f"Missing runner script: {SCRIPT}"
    receipt = tmp_path / "receipt.json"
    result = invoke("--job", "nonexistent-job", "--receipt", str(receipt))
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
    assert not receipt.exists()


def test_default_offline_marks_dependency_audit_unavailable_and_exits_one(
    tmp_path: Path, monkeypatch
) -> None:
    receipt = tmp_path / "offline-audit.json"
    result = invoke("--job", "dependency-audit", "--receipt", str(receipt))
    assert result.returncode == 1
    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["status"] == "failed"
    assert data["allow_online"] is False
    assert data["provider_verified"] is False
    assert data["release_accepted"] is False
    audit_record = data["jobs"]["dependency-audit"]
    assert audit_record["status"] == "unavailable"
    assert audit_record["network"] == "deny"
    assert audit_record["commands"] == []
    assert "pip-audit" in audit_record["reason"]

    module = load_gate_module()
    monkeypatch.setattr(module, "OUTPUT", str(tmp_path / "gate-out"))
    for job_name in OFFLINE_JOBS:
        monkeypatch.setitem(
            module.JOBS,
            job_name,
            module.JobSpec(
                commands=([sys.executable, "-c", "pass"],),
                network="deny",
                workflow=f"test:{job_name}",
            ),
        )
    full_receipt = tmp_path / "full-offline.json"
    full_code = module.main(["--receipt", str(full_receipt)])
    assert full_code == 1
    full_data = json.loads(full_receipt.read_text(encoding="utf-8"))
    assert full_data["status"] == "failed"
    for job_name in OFFLINE_JOBS:
        assert full_data["jobs"][job_name]["status"] == "passed"
    assert full_data["jobs"]["dependency-audit"]["status"] == "unavailable"


def test_allow_online_enforces_outbound_only_sandbox_and_keeps_offline_jobs_denied(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_gate_module()
    monkeypatch.setattr(module, "OUTPUT", str(tmp_path / "gate-out"))

    bound_marker = tmp_path / "bound"
    bind_probe = [
        sys.executable,
        "-c",
        "import socket; from pathlib import Path; "
        "s = socket.socket(); s.bind(('', 0)); "
        f"Path({str(bound_marker)!r}).touch()",
    ]
    bind_results = module.run_commands(
        [bind_probe], tmp_path / "outbound-bind", network_policy="outbound-permitted"
    )
    assert bind_results[0]["exit_code"] in (1, 71)
    assert not bound_marker.exists()

    captured_argvs: list[list[str]] = []
    real_run = subprocess.run

    def spy_run(argv, *args, **kwargs):
        captured_argvs.append([str(part) for part in argv])
        if any(str(part).endswith("pip-audit") for part in argv):
            return subprocess.CompletedProcess(argv, 0)
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", spy_run)
    monkeypatch.setitem(
        module.JOBS,
        "smoke-tests",
        module.JobSpec(
            commands=([sys.executable, "-c", "pass"],),
            network="deny",
            workflow="test:smoke",
        ),
    )

    receipt = tmp_path / "online-receipt.json"
    code = module.main(
        [
            "--allow-online",
            "--job",
            "dependency-audit",
            "--job",
            "smoke-tests",
            "--receipt",
            str(receipt),
        ]
    )
    assert code == 0
    assert len(captured_argvs) == 2

    audit_argv, smoke_argv = captured_argvs
    assert audit_argv[2].startswith("(version 1) (allow default) (deny network*)")
    assert '(remote tcp "*:443")' in audit_argv[2]
    assert audit_argv[-2:] == ["--index-url", "https://pypi.org/simple/"]
    assert smoke_argv[2] == "(version 1) (allow default) (deny network*)"

    data = json.loads(receipt.read_text(encoding="utf-8"))
    assert data["status"] == "passed"
    assert data["allow_online"] is True
    assert (
        data["jobs"]["dependency-audit"]["network"]
        == "outbound-permitted (inbound/bind denied)"
    )
    assert data["jobs"]["smoke-tests"]["network"] == "deny"


def test_secret_scan_catches_staged_secret_with_clean_unstaged_diff(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_gate_module()
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    shutil.copy2(ROOT / ".gitleaks.toml", repo_dir / ".gitleaks.toml")

    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True,
        )

    git("init")
    git("config", "user.email", "ci-test@example.invalid")
    git("config", "user.name", "CI Test")
    (repo_dir / "README.md").write_text("# Clean fixture\n", encoding="utf-8")
    git("add", "README.md", ".gitleaks.toml")
    git("commit", "-m", "chore: initial clean commit")
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    (repo_dir / "scripts").mkdir()
    shutil.copy2(SCRIPT, repo_dir / "scripts" / SCRIPT.name)

    fake_secret = "ghp_" + "".join(
        chr(ord("A") + (i % 26)) if i % 2 == 0 else str(i % 10) for i in range(36)
    )
    gate_noise = repo_dir / ".gate" / "local-ci" / "noise.log"
    gate_noise.parent.mkdir(parents=True, exist_ok=True)
    gate_noise.write_text(f"ignored gate artifact {fake_secret}\n", encoding="utf-8")
    pyc_noise = repo_dir / "server" / "observability" / "__pycache__" / "stub.pyc"
    pyc_noise.parent.mkdir(parents=True, exist_ok=True)
    pyc_noise.write_text(f'api_key = "{fake_secret}"\n', encoding="utf-8")

    monkeypatch.setattr(module, "ROOT", repo_dir)
    clean_results = module.run_commands(
        module.JOBS["secret-scan"].commands, repo_dir / ".gate" / "clean-logs"
    )
    assert [row["exit_code"] for row in clean_results] == [0]

    candidate = repo_dir / "staged_only.py"
    candidate.write_text(f'TOKEN = "{fake_secret}"\n', encoding="utf-8")
    git("add", "staged_only.py")
    unstaged = git("diff")
    assert unstaged.stdout == ""

    staged_results = module.run_commands(
        module.JOBS["secret-scan"].commands, repo_dir / ".gate" / "staged-logs"
    )
    assert [row["exit_code"] for row in staged_results] == [1]
    log = (repo_dir / ".gate/staged-logs" / staged_results[0]["log"]).read_text()
    assert log.splitlines() == ["staged_only.py:1", "added-line findings: 1"]
    assert fake_secret not in log

    git("commit", "-m", "synthetic scanner fixture")
    committed = module.added_line_scan()
    assert committed == 1
    git("update-ref", "refs/remotes/origin/main", "HEAD")
    assert module.added_line_scan() == 0
    candidate.write_text(f'TOKEN = "{fake_secret}"\nSECOND = "{fake_secret}"\n')
    assert module.added_line_scan() == 1
    git("update-ref", "-d", "refs/remotes/origin/main")
    assert module.added_line_scan() == 1


def test_online_audit_denies_credentials_and_creates_distinct_empty_configs(
    tmp_path: Path, monkeypatch
) -> None:
    _require_outer_socket_permission()
    module = load_gate_module()
    workspace = tmp_path.resolve() / "workspace"
    host_home = tmp_path.resolve() / "host-home"
    workspace.mkdir()
    host_home.mkdir()
    credential_paths = [
        workspace / ".env",
        workspace / "server/.env.local",
        workspace / ".npmrc",
        host_home / ".ssh/canary",
        host_home / ".config/gh/hosts.yml",
        host_home / ".netrc",
        host_home / ".git-credentials",
    ]
    for path in credential_paths:
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text("synthetic marker")
    ca_bundle = workspace / ".gate/venv/lib/certifi/cacert.pem"
    ca_bundle.parent.mkdir(parents=True)
    ca_bundle.write_text("synthetic CA bundle")
    monkeypatch.setattr(module, "ROOT", workspace)
    monkeypatch.setattr("pwd.getpwuid", lambda _: SimpleNamespace(pw_dir=str(host_home)))
    probe = """
import os
from pathlib import Path
import stat
import sys
assert Path(sys.argv[1]).read_text() == 'synthetic CA bundle'
for path in map(Path, sys.argv[2:]):
    try:
        path.read_bytes()
    except PermissionError:
        continue
    raise SystemExit(11)
assert 'PYTHONPATH' not in os.environ
keys = ('PIP_CONFIG_FILE', 'NPM_CONFIG_USERCONFIG', 'NPM_CONFIG_GLOBALCONFIG')
configs = {Path(os.environ[key]) for key in keys}
assert len(configs) == len(keys)
for config in configs:
    assert config.is_relative_to(os.environ['HOME'])
    assert config.read_bytes() == b''
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
"""
    result = module.run_commands(
        [[sys.executable, "-c", probe, str(ca_bundle), *map(str, credential_paths)]],
        tmp_path.resolve() / "logs",
        network_policy="outbound-permitted",
    )
    assert result[0]["exit_code"] == 0


def test_tflint_can_use_only_its_private_unix_sockets(tmp_path: Path, monkeypatch) -> None:
    _require_outer_socket_permission()
    module = load_gate_module()
    monkeypatch.setattr(module, "ROOT", tmp_path.resolve())
    tool = _write_executable(
        tmp_path / ".gate/bin/tflint",
        f"#!{sys.executable}\n"
        "import os, socket\n"
        "with socket.socket(socket.AF_UNIX) as server:\n"
        "    path = os.path.join(os.environ['TMPDIR'], 'plugin.sock')\n"
        "    server.bind(path)\n"
        "    server.listen()\n"
        "    with socket.socket(socket.AF_UNIX) as client:\n"
        "        client.connect(path)\n"
        "for family, address in [(socket.AF_UNIX, 'outside.sock'), "
        "(socket.AF_INET, ('', 0))]:\n"
        "    with socket.socket(family) as server:\n"
        "        try:\n"
        "            server.bind(address)\n"
        "        except PermissionError:\n"
        "            continue\n"
        "        raise SystemExit(12)\n",
    )
    assert tool.is_file()
    result = module.run_commands([["tflint"]], tmp_path.resolve() / "logs")
    assert result[0]["exit_code"] == 0


def test_environment_precedence_prefers_designated_repo_venv_over_unrelated_venv(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_gate_module()
    fake_root = tmp_path / "repo"
    fake_root.mkdir()
    marker = tmp_path / "which-env.txt"

    def make_tool(bin_dir: Path, name: str, label: str) -> Path:
        script = (
            "#!/bin/sh\n"
            f'printf "%s:%s\\n" "{label}" "{name}" >> "{marker}"\n'
        )
        return _write_executable(bin_dir / name, script)

    base_root = tmp_path / "base-py"
    base_bin = base_root / "bin"
    make_tool(base_bin, "python3", "base")
    make_tool(base_bin, "bandit", "base")

    unrelated_venv = tmp_path / "unrelated-venv"
    unrelated_bin = unrelated_venv / "bin"
    make_tool(unrelated_bin, "python3", "unrelated")
    make_tool(unrelated_bin, "bandit", "unrelated")
    make_tool(unrelated_bin, "ruff", "unrelated")

    monkeypatch.setattr(module, "ROOT", fake_root)
    monkeypatch.setattr(module.sys, "executable", str(base_bin / "python3"))
    monkeypatch.setattr(module.sys, "prefix", str(base_root))
    monkeypatch.setattr(module.sys, "base_prefix", str(base_root))
    monkeypatch.setenv("PATH", f"{base_bin}{os.pathsep}/usr/bin{os.pathsep}/bin")

    base_res = module.run_commands(
        [["python3"], ["bandit"], ["definitely-missing-tool-xyz"]],
        tmp_path / "logs-base",
    )
    assert [r["exit_code"] for r in base_res] == [0, 0, 127]
    assert marker.read_text(encoding="utf-8").splitlines() == [
        "base:python3",
        "base:bandit",
    ]

    marker.unlink()
    gate_bin = fake_root / ".gate" / "venv" / "bin"
    make_tool(gate_bin, "python3", "gate-venv")
    make_tool(gate_bin, "bandit", "gate-venv")

    monkeypatch.setattr(module.sys, "executable", str(unrelated_bin / "python3"))
    monkeypatch.setattr(module.sys, "prefix", str(unrelated_venv))
    monkeypatch.setattr(module.sys, "base_prefix", str(base_root))
    monkeypatch.setenv("VIRTUAL_ENV", str(unrelated_venv))
    monkeypatch.setenv(
        "PATH",
        f"{unrelated_bin}{os.pathsep}{base_bin}{os.pathsep}/usr/bin{os.pathsep}/bin",
    )

    override_res = module.run_commands(
        [["python3"], ["bandit"], ["ruff"]],
        tmp_path / "logs-unrelated",
    )
    assert [r["exit_code"] for r in override_res] == [0, 0, 127]
    assert marker.read_text(encoding="utf-8").splitlines() == [
        "gate-venv:python3",
        "gate-venv:bandit",
    ]

    marker.unlink()
    make_tool(gate_bin, "ruff", "gate-venv")
    present_res = module.run_commands([["ruff"]], tmp_path / "logs-present")
    assert [r["exit_code"] for r in present_res] == [0]
    assert marker.read_text(encoding="utf-8").splitlines() == ["gate-venv:ruff"]

    marker.unlink()
    shutil.rmtree(fake_root / ".gate" / "venv")
    dot_venv_bin = fake_root / ".venv" / "bin"
    make_tool(dot_venv_bin, "python3", "dot-venv")
    fallback_res = module.run_commands([["python3"]], tmp_path / "logs-dot-venv")
    assert [r["exit_code"] for r in fallback_res] == [0]
    assert marker.read_text(encoding="utf-8").splitlines() == ["dot-venv:python3"]


def test_minimal_env_allowlist_strips_secrets_isolates_home_and_creates_atomic_0600_files(
    tmp_path: Path, monkeypatch
) -> None:
    module = load_gate_module()
    monkeypatch.setattr(module, "OUTPUT", str(tmp_path / "gate-out"))

    secret_vars = {
        "OCI_TENANCY_PROBE": "sensitive-oci",
        "AWS_SECRET_ACCESS_KEY": "sensitive-aws",
        "AZURE_CLIENT_SECRET": "sensitive-azure",
        "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/sensitive-gcp.json",
        "GH_TOKEN": "sensitive-gh",
        "GITHUB_TOKEN": "sensitive-github",
        "ARM_CLIENT_SECRET": "sensitive-arm",
        "PGPASSWORD": "sensitive-pg",
        "DB_PASSWORD": "sensitive-db",
        "PIP_INDEX_URL": "https://private.example.invalid/simple",
        "UNLISTED_AMBIENT_SECRET": "sensitive-custom",
    }
    for key, value in secret_vars.items():
        monkeypatch.setenv(key, value)

    caller_home = os.path.expanduser("~")
    env_dump = tmp_path / "env.json"
    commands = [
        [sys.executable, "-c", "raise SystemExit(7)"],
        [
            sys.executable,
            "-c",
            "import json, os; from pathlib import Path; "
            f"Path({str(env_dump)!r}).write_text(json.dumps(dict(os.environ)))",
        ],
        [sys.executable, "-c", "import socket; s = socket.socket(); s.bind(('', 0))"],
        ["definitely-missing-local-ci-binary-xyz"],
    ]

    open_modes: list[tuple[Path, int]] = []
    real_os_open = os.open

    def spy_os_open(path, flags, mode=0o777, *args, **kwargs):
        if flags & os.O_CREAT:
            open_modes.append((Path(path), mode))
        return real_os_open(path, flags, mode, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", spy_os_open)

    log_dir = tmp_path / "logs"
    results = module.run_commands(commands, log_dir)
    assert [row["exit_code"] for row in results] == [7, 0, 1, 127]

    observed = json.loads(env_dump.read_text(encoding="utf-8"))
    for forbidden in secret_vars:
        assert forbidden not in observed, f"Leaked env var: {forbidden}"

    allowed_keys = {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TMPDIR",
        "USER",
        "LOGNAME",
        "SHELL",
        "HOME",
        "OCI_AUTH_MODE",
        "OCI_CONFIG_FILE",
        "PIP_CONFIG_FILE",
        "PIP_NO_CACHE_DIR",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
        "__CF_USER_TEXT_ENCODING",
    }
    assert set(observed) <= allowed_keys
    assert observed["HOME"] != caller_home
    assert observed["OCI_CONFIG_FILE"] == "/dev/null"

    for row in results:
        log_path = log_dir / row["log"]
        assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
        assert any(
            mode == 0o600 and temporary.parent == log_path.parent
            and temporary.name.startswith(f".{log_path.name}.")
            for temporary, mode in open_modes
        )

    preexisting_receipt = tmp_path / "preexisting-receipt.json"
    preexisting_receipt.write_text("{}", encoding="utf-8")
    preexisting_receipt.chmod(0o644)
    monkeypatch.setitem(
        module.JOBS,
        "synthetic-pass",
        module.JobSpec(
            commands=([sys.executable, "-c", "pass"],),
            network="deny",
            workflow="test:pass",
        ),
    )
    assert (
        module.main(["--job", "synthetic-pass", "--receipt", str(preexisting_receipt)])
        == 0
    )
    assert stat.S_IMODE(preexisting_receipt.stat().st_mode) == 0o600
    assert any(
        path.name.startswith(".preexisting-receipt.json.") and mode == 0o600
        for path, mode in open_modes
    )


def test_cli_writes_private_receipt_and_propagates_pass_and_fail(
    tmp_path: Path, monkeypatch
) -> None:
    pass_receipt = tmp_path / "pass-receipt.json"
    passed = invoke("--job", "smoke-tests", "--receipt", str(pass_receipt))
    assert passed.returncode == 0, passed.stderr
    assert stat.S_IMODE(pass_receipt.stat().st_mode) == 0o600

    pass_data = json.loads(pass_receipt.read_text(encoding="utf-8"))
    assert pass_data["status"] == "passed"
    assert pass_data["allow_online"] is False
    assert pass_data["provider_verified"] is False
    assert pass_data["release_accepted"] is False
    assert pass_data["jobs"]["smoke-tests"]["status"] == "passed"
    assert pass_data["excluded_workflow_checks"]
    assert all(
        item["status"] != "passed"
        for item in pass_data["excluded_workflow_checks"].values()
    )

    module = load_gate_module()
    monkeypatch.setattr(module, "OUTPUT", str(tmp_path / "gate-out"))
    fail_receipt = tmp_path / "fail-receipt.json"
    monkeypatch.setitem(
        module.JOBS,
        "synthetic-fail",
        module.JobSpec(
            commands=([sys.executable, "-c", "raise SystemExit(3)"],),
            network="deny",
            workflow="test:synthetic",
        ),
    )
    code = module.main(["--job", "synthetic-fail", "--receipt", str(fail_receipt)])
    assert code == 1
    fail_data = json.loads(fail_receipt.read_text(encoding="utf-8"))
    assert fail_data["status"] == "failed"
    assert fail_data["jobs"]["synthetic-fail"]["status"] == "failed"
    assert fail_data["jobs"]["synthetic-fail"]["commands"][0]["exit_code"] == 3


def test_no_mistakes_runs_the_aggregate_with_isolated_audit_and_offline_lint() -> None:
    assert CONFIG.is_file(), f"Missing config: {CONFIG}"
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert set(config.keys()) == {"commands", "auto_fix"}
    assert set(config["commands"].keys()) == {"test", "lint"}
    assert (
        config["commands"]["test"]
        == "python3.11 scripts/local_ci_gate.py --allow-online"
    )
    assert config["commands"]["lint"].startswith(
        "python3.11 scripts/local_ci_gate.py --job "
    )
    assert "--allow-online" not in config["commands"]["lint"]
    assert "dependency-audit" not in config["commands"]["lint"]
    for key in ("test", "lint"):
        assert "||" not in config["commands"][key]
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
