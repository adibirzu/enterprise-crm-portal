#!/usr/bin/env python3.11
"""Run the local no-mistakes CI gate for enterprise-crm-portal with private receipts.

All jobs run inside macOS sandbox-exec with network denied by default, an isolated
temporary HOME, a minimal environment allowlist, and atomic 0600 logs and receipts.
Dependency auditing requires explicit --allow-online opt-in, which runs under
outbound-permitted (inbound/bind denied) sandbox-exec while keeping offline jobs
strictly network-denied.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ".gate/local-ci"
SANDBOX_DENY_NET = "(version 1) (allow default) (deny network*)"
SANDBOX_OUTBOUND_ONLY = (
    "(version 1) (allow default) (deny network-inbound) (deny network-bind)"
)
ONLINE_NETWORK_LABEL = "outbound-permitted (inbound/bind denied)"
UNAVAILABLE_OFFLINE_AUDIT_REASON = (
    "pip-audit -r requirements.txt --strict requires outbound network access to "
    "live advisory registries and creates a temporary pip resolver virtualenv; "
    "network is denied by default. Pass --allow-online explicitly when approved."
)
SAFE_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "USER",
    "LOGNAME",
    "SHELL",
)
DESIGNATED_VENV_BINS = (
    Path(".gate") / "venv" / "bin",
    Path(".venv") / "bin",
    Path(".venv311") / "bin",
)
PYTHON_TOOLS = frozenset(
    {
        "python",
        "python3",
        "python3.11",
        "pytest",
        "bandit",
        "ruff",
        "mkdocs",
        "pip-audit",
    }
)


@dataclass(frozen=True)
class JobSpec:
    commands: Sequence[Sequence[str]]
    network: str = "deny"
    workflow: str = ""
    requires_online: bool = False
    available: bool = True
    reason: str | None = None


JOBS: dict[str, JobSpec] = {
    "unit-tests": JobSpec(
        commands=(["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider"],),
        network="deny",
        workflow="local:pytest-full-suite",
    ),
    "smoke-tests": JobSpec(
        commands=(
            [
                "python3",
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/test_health.py",
                "tests/test_observability_frontend.py",
            ],
        ),
        network="deny",
        workflow="local:offline-smoke",
    ),
    "python-sast": JobSpec(
        commands=(
            ["bandit", "-q", "-r", "server", "-x", "server/__pycache__", "-ll", "-iii"],
            ["ruff", "check", "--no-cache", "--select", "S", "server"],
        ),
        network="deny",
        workflow="security-gates.yml:python-sast",
    ),
    "dependency-audit": JobSpec(
        commands=(["pip-audit", "-r", "requirements.txt", "--strict"],),
        network="deny",
        workflow="security-gates.yml:python-sast(pip-audit)",
        requires_online=True,
    ),
    "secret-scan": JobSpec(
        commands=(
            ["gitleaks", "detect", "--source", ".", "--redact", "--no-banner"],
            [
                "gitleaks",
                "git",
                "--pre-commit",
                "--staged",
                "--redact",
                "--no-banner",
            ],
            ["gitleaks", "git", "--pre-commit", "--redact", "--no-banner"],
            ["gitleaks", "dir", ".", "--redact", "--no-banner"],
        ),
        network="deny",
        workflow="security-gates.yml:secret-scan",
    ),
    "mkdocs-build": JobSpec(
        commands=(
            ["mkdocs", "build", "--strict", "--site-dir", f"{OUTPUT}/mkdocs-site"],
        ),
        network="deny",
        workflow="mkdocs-deploy.yml:build-and-deploy",
    ),
    "container-scan": JobSpec(
        commands=(
            [
                "trivy",
                "config",
                "--skip-check-update",
                "--skip-version-check",
                "--severity",
                "HIGH,CRITICAL",
                "--exit-code",
                "1",
                "Dockerfile",
            ],
        ),
        network="deny",
        workflow="security-gates.yml:container-scan(Dockerfile)",
    ),
}

EXCLUDED_WORKFLOW_CHECKS: dict[str, dict[str, str]] = {
    "security-gates.yml:python-sast:semgrep": {
        "status": "unverified_offline",
        "reason": (
            "semgrep ci downloads remote rulesets and cloud policy from semgrep.dev; "
            "cloud calls are prohibited in this local gate."
        ),
    },
    "security-gates.yml:node-audit": {
        "status": "not_applicable",
        "reason": "Repository has no package.json or Node.js lockfile.",
    },
    "security-gates.yml:terraform-lint": {
        "status": "not_applicable",
        "reason": "Repository has no deploy/terraform directory or .tf files.",
    },
    "security-gates.yml:container-scan:k8s-manifests": {
        "status": "unverified_in_gate",
        "reason": (
            "Dockerfile is gated with --exit-code 1; deploy/k8s/*.yaml carry pre-existing "
            "KSV-0014/KSV-0118 findings while workflow trivy-action omits exit-code: 1."
        ),
    },
    "mkdocs-deploy.yml:build-and-deploy:gh-pages": {
        "status": "out_of_scope",
        "reason": "Remote GitHub Pages deployment is outside local validation.",
    },
}


def _open_private_write(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


def _designated_venv_bins(root: Path) -> list[Path]:
    return [
        (root / rel).absolute()
        for rel in DESIGNATED_VENV_BINS
        if (root / rel).is_dir()
    ]


def _resolve_executable(
    name: str,
    repo_bins: Sequence[Path],
    search_path: str,
) -> str | None:
    if os.sep in name or (os.altsep and os.altsep in name):
        candidate = Path(name)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None

    if repo_bins and name in PYTHON_TOOLS:
        venv_search = os.pathsep.join(str(p) for p in repo_bins)
        resolved = shutil.which(name, path=venv_search)
        if resolved is None and name == "python3":
            resolved = shutil.which("python", path=venv_search)
        return resolved

    resolved = shutil.which(name, path=search_path)
    if resolved is None and name == "python3":
        fallback = Path(sys.executable).absolute()
        if fallback.is_file() and os.access(fallback, os.X_OK):
            return str(fallback)
    return resolved


def _sandbox_profile(network_policy: str) -> str:
    if network_policy == "deny":
        return SANDBOX_DENY_NET
    if network_policy == "outbound-permitted":
        return SANDBOX_OUTBOUND_ONLY
    raise ValueError(f"Unsupported network policy: {network_policy}")


def run_commands(
    commands: Sequence[Sequence[str]],
    output: Path | str,
    *,
    network_policy: str = "deny",
) -> list[dict[str, object]]:
    """Execute argv commands under macOS sandbox-exec and retain every exit code."""
    profile = _sandbox_profile(network_policy)
    if platform.system() != "Darwin" or not shutil.which("sandbox-exec"):
        raise RuntimeError("macOS sandbox-exec required; refusing unisolated execution")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_dir, 0o700)

    repo_bins = _designated_venv_bins(ROOT)
    current_bin = Path(sys.executable).absolute().parent
    prefix_bins = [str(p) for p in repo_bins] if repo_bins else [str(current_bin)]

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="local-ci-home-") as home:
        env: dict[str, str] = {}
        for key in SAFE_ENV_KEYS:
            if key in os.environ:
                env[key] = os.environ[key]
        existing_path = env["PATH"] if "PATH" in env else os.defpath
        env.update(
            HOME=home,
            PATH=os.pathsep.join([*prefix_bins, existing_path]),
            OCI_AUTH_MODE="config",
            OCI_CONFIG_FILE="/dev/null",
            PIP_CONFIG_FILE="/dev/null",
            PIP_NO_CACHE_DIR="1",
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONPATH=str(ROOT),
        )
        for index, raw_command in enumerate(commands):
            command = [str(part) for part in raw_command]
            log = output_dir / f"{index:02d}.log"
            with _open_private_write(log) as stream:
                resolved = _resolve_executable(command[0], repo_bins, env["PATH"])
                if resolved is None:
                    stream.write(f"Local command unavailable: {command[0]}\n")
                    code = 127
                else:
                    argv = [
                        "sandbox-exec",
                        "-p",
                        profile,
                        resolved,
                        *command[1:],
                    ]
                    try:
                        proc = subprocess.run(
                            argv,
                            cwd=ROOT,
                            env=env,
                            stdout=stream,
                            stderr=subprocess.STDOUT,
                            timeout=300,
                            check=False,
                        )
                        code = proc.returncode
                    except (OSError, subprocess.TimeoutExpired) as error:
                        stream.write(f"Local command failed: {type(error).__name__}\n")
                        code = (
                            124
                            if isinstance(error, subprocess.TimeoutExpired)
                            else 127
                        )
            results.append({"command": command, "exit_code": code, "log": log.name})
    return results


def _effective_job_state(
    spec: JobSpec, *, allow_online: bool
) -> tuple[bool, str, str | None, str]:
    if not spec.available:
        return False, spec.network, spec.reason, "deny"
    if spec.requires_online:
        if not allow_online:
            return False, "deny", UNAVAILABLE_OFFLINE_AUDIT_REASON, "deny"
        return True, ONLINE_NETWORK_LABEL, None, "outbound-permitted"
    return True, "deny", None, "deny"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--allow-online", action="store_true")
    parser.add_argument("--job", choices=tuple(JOBS), action="append")
    parser.add_argument(
        "--receipt",
        type=Path,
        default=ROOT / OUTPUT / "receipt.json",
    )
    args = parser.parse_args(argv)

    if args.list:
        listing: dict[str, dict[str, object]] = {}
        for name, spec in JOBS.items():
            available, network_label, reason, _ = _effective_job_state(
                spec, allow_online=args.allow_online
            )
            listing[name] = {
                "commands": [list(cmd) for cmd in spec.commands],
                "available": available,
                "network": network_label,
                "workflow": spec.workflow,
                "reason": reason,
            }
        print(json.dumps(listing, indent=2))
        return 0

    output_root = ROOT / OUTPUT
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_root, 0o700)

    records: dict[str, dict[str, object]] = {}
    selected_jobs = args.job or list(JOBS)
    for job_name in selected_jobs:
        spec = JOBS[job_name]
        available, network_label, reason, network_policy = _effective_job_state(
            spec, allow_online=args.allow_online
        )
        if not available:
            record: dict[str, object] = {
                "status": "unavailable",
                "network": network_label,
                "workflow": spec.workflow,
                "reason": reason,
                "commands": [],
            }
        else:
            try:
                results = run_commands(
                    spec.commands,
                    output_root / job_name,
                    network_policy=network_policy,
                )
                passed = bool(results) and all(r["exit_code"] == 0 for r in results)
                record = {
                    "status": "passed" if passed else "failed",
                    "network": network_label,
                    "workflow": spec.workflow,
                    "commands": results,
                }
            except RuntimeError as error:
                record = {
                    "status": "unavailable",
                    "network": network_label,
                    "workflow": spec.workflow,
                    "reason": str(error),
                    "commands": [],
                }
        records[job_name] = record
        print(f"{job_name}: {record['status']}", flush=True)

    success = all(record["status"] == "passed" for record in records.values())
    receipt = {
        "schema": "enterprise-crm-portal.local-ci/v1",
        "status": "passed" if success else "failed",
        "allow_online": bool(args.allow_online),
        "provider_verified": False,
        "release_accepted": False,
        "jobs": records,
        "excluded_workflow_checks": EXCLUDED_WORKFLOW_CHECKS,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _open_private_write(args.receipt) as receipt_stream:
        receipt_stream.write(json.dumps(receipt, indent=2) + "\n")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
