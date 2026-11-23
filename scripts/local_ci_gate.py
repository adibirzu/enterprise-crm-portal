#!/usr/bin/env python3.11
"""Run the local no-mistakes CI gate for enterprise-crm-portal with private receipts.

Offline jobs run inside macOS sandbox-exec with network access denied, a temporary
HOME, and cloud credentials stripped. Dependency auditing uses read-only advisory
resolution without failure masking.
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
PYTHON = Path(sys.executable).name
SANDBOX_DENY_NET = "(version 1) (allow default) (deny network*)"


@dataclass(frozen=True)
class JobSpec:
    commands: Sequence[Sequence[str]]
    network: str = "deny"
    workflow: str = ""
    available: bool = True
    reason: str | None = None


JOBS: dict[str, JobSpec] = {
    "unit-tests": JobSpec(
        commands=([PYTHON, "-m", "pytest", "-q", "-p", "no:cacheprovider"],),
        network="deny",
        workflow="local:pytest-full-suite",
    ),
    "smoke-tests": JobSpec(
        commands=(
            [
                PYTHON,
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
        network="advisory-fetch",
        workflow="security-gates.yml:python-sast(pip-audit)",
    ),
    "secret-scan": JobSpec(
        commands=(
            ["gitleaks", "detect", "--source", ".", "--redact", "--no-banner"],
            ["gitleaks", "git", "--pre-commit", "--redact", "--no-banner"],
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


def _preferred_bin_dirs() -> list[str]:
    current_bin = str(Path(sys.executable).absolute().parent)
    gate_venv_bin = ROOT / ".gate" / "venv" / "bin"
    if sys.prefix == sys.base_prefix and gate_venv_bin.is_dir():
        return [str(gate_venv_bin), current_bin]
    return [current_bin]


def run_commands(
    commands: Sequence[Sequence[str]],
    output: Path | str,
    *,
    isolate_network: bool = True,
) -> list[dict[str, object]]:
    """Execute argv commands without a shell and retain every exit code."""
    if isolate_network and (
        platform.system() != "Darwin" or not shutil.which("sandbox-exec")
    ):
        raise RuntimeError("macOS sandbox-exec required; refusing unisolated execution")

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_dir, 0o700)

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="local-ci-home-") as home:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("OCI_", "AWS_", "AZURE_", "GOOGLE_"))
        }
        existing_path = env["PATH"] if "PATH" in env else os.defpath
        env.update(
            HOME=home,
            PATH=os.pathsep.join([*_preferred_bin_dirs(), existing_path]),
            OCI_AUTH_MODE="config",
            OCI_CONFIG_FILE="/dev/null",
            PIP_NO_CACHE_DIR="1",
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONPATH=str(ROOT),
        )
        for index, raw_command in enumerate(commands):
            command = [str(part) for part in raw_command]
            log = output_dir / f"{index:02d}.log"
            with log.open("w", encoding="utf-8") as stream:
                os.chmod(log, 0o600)
                resolved = shutil.which(command[0], path=env["PATH"])
                if resolved is None:
                    stream.write(f"Local command unavailable: {command[0]}\n")
                    code = 127
                else:
                    argv = [resolved, *command[1:]]
                    if isolate_network:
                        argv = ["sandbox-exec", "-p", SANDBOX_DENY_NET, *argv]
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
                        code = 124 if isinstance(error, subprocess.TimeoutExpired) else 127
            results.append({"command": command, "exit_code": code, "log": log.name})
    return results


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--job", choices=tuple(JOBS), action="append")
    parser.add_argument(
        "--receipt",
        type=Path,
        default=ROOT / OUTPUT / "receipt.json",
    )
    args = parser.parse_args(argv)

    if args.list:
        listing = {
            name: {
                "commands": [list(cmd) for cmd in spec.commands],
                "available": spec.available,
                "network": spec.network,
                "workflow": spec.workflow,
                "reason": spec.reason,
            }
            for name, spec in JOBS.items()
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
        if not spec.available:
            record: dict[str, object] = {
                "status": "unavailable",
                "network": spec.network,
                "workflow": spec.workflow,
                "reason": spec.reason,
                "commands": [],
            }
        else:
            try:
                results = run_commands(
                    spec.commands,
                    output_root / job_name,
                    isolate_network=(spec.network == "deny"),
                )
                passed = bool(results) and all(r["exit_code"] == 0 for r in results)
                record = {
                    "status": "passed" if passed else "failed",
                    "network": spec.network,
                    "workflow": spec.workflow,
                    "commands": results,
                }
            except RuntimeError as error:
                record = {
                    "status": "unavailable",
                    "network": spec.network,
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
        "provider_verified": False,
        "release_accepted": False,
        "jobs": records,
        "excluded_workflow_checks": EXCLUDED_WORKFLOW_CHECKS,
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    os.chmod(args.receipt, 0o600)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
