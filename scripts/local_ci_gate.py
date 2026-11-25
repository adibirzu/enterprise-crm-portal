#!/usr/bin/env python3.11
"""Run the local no-mistakes CI gate for enterprise-crm-portal with private receipts.

All jobs run inside macOS Seatbelt with a temporary HOME and private logs.
Only dependency auditing can opt into HTTPS and system DNS.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ".gate/local-ci"
SANDBOX_DENY_NET = "(version 1) (allow default) (deny network*)"
ONLINE_NETWORK_LABEL = "outbound-permitted (inbound/bind denied)"
UNAVAILABLE_OFFLINE_AUDIT_REASON = (
    "pip-audit and npm audit require live advisory registries. Pass --allow-online."
)
SAFE_ENV_KEYS = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
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
        "semgrep",
    }
)


@dataclass(frozen=True)
class JobSpec:
    commands: Sequence[Sequence[str]]
    network: str = "deny"
    workflow: str = ""
    requires_online: bool = False


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
            [
                "semgrep", "scan", "--error", "--quiet", "--metrics=off",
                "--disable-version-check",
                "--config", ".gate/semgrep-rules/owasp-top-ten.yml",
                "--config", ".gate/semgrep-rules/python.yml",
                "--config", ".gate/semgrep-rules/fastapi.yml",
                ".",
            ],
        ),
        network="deny",
        workflow="security-gates.yml:python-sast",
    ),
    "dependency-audit": JobSpec(
        commands=(
            [
                "pip-audit", "-r", "requirements.txt", "--strict",
                "--progress-spinner", "off", "--index-url", "https://pypi.org/simple/",
            ],
        ),
        workflow="security-gates.yml:python-sast(pip-audit)",
        requires_online=True,
    ),
    "node-audit": JobSpec(
        commands=(
            [
                "npm", "audit", "--omit=dev", "--audit-level=high", "--package-lock-only",
                "--ignore-scripts", "--registry=https://registry.npmjs.org/",
            ],
        ),
        workflow="security-gates.yml:node-audit",
        requires_online=True,
    ),
    "secret-scan": JobSpec(
        commands=(["python3", "scripts/local_ci_gate.py", "--added-line-scan"],),
        workflow="security-gates.yml:secret-scan",
    ),
    "terraform-lint": JobSpec(
        commands=(
            ["terraform", "-chdir=deploy/terraform", "fmt", "-check", "-recursive"],
            ["tflint", "--init"],
            ["tflint", "--chdir=deploy/terraform", "--recursive"],
        ),
        workflow="security-gates.yml:terraform-lint",
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
                "--skip-dirs", ".gate",
                "--skip-dirs", ".git",
                "--skip-dirs", ".venv",
                "--skip-dirs", ".venv311",
                "--skip-dirs", "node_modules",
                ".",
            ],
        ),
        network="deny",
        workflow="security-gates.yml:container-scan",
    ),
}

EXCLUDED_WORKFLOW_CHECKS: dict[str, dict[str, str]] = {
    "mkdocs-deploy.yml:build-and-deploy:gh-pages": {
        "status": "out_of_scope",
        "reason": "Remote GitHub Pages deployment is outside local validation.",
    },
}


def _private_directory(path: Path) -> None:
    for part in (*reversed(path.absolute().parents), path.absolute()):
        if part.is_symlink():
            raise RuntimeError("Local CI output cannot use a symlink")
        part.mkdir(mode=0o700, exist_ok=True)
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RuntimeError("Local CI output directory must be private")


@contextmanager
def _open_private_write(path: Path):
    if path.is_symlink():
        raise RuntimeError("Local CI output file cannot be a symlink")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            yield stream
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


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


def _audit_profile(host_home: Path) -> str:
    workspace = json.dumps(str(ROOT.resolve()))
    profile = (
        SANDBOX_DENY_NET
        + ' (allow network-outbound (remote tcp "*:443")'
        ' (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))'
        f" (deny file-write* (subpath {json.dumps(str(host_home))}) (subpath {workspace}))"
    )
    directories = (
        ".ssh", ".oci", ".aws", ".kube", ".azure", ".docker", ".gnupg", ".config/gh",
        ".config/gcloud", ".config/pip", ".config/git", ".local/share/keyrings", ".npm",
        ".pip", "Library/Keychains", "Library/Application Support/pip",
    )
    for directory in directories:
        profile += f" (deny file-read* (subpath {json.dumps(str(host_home / directory))}))"
    files = (
        host_home / ".netrc", host_home / ".npmrc", host_home / ".pypirc",
        host_home / ".git-credentials", host_home / ".gitconfig",
        Path("/private/etc/pip.conf"), Path("/Library/Application Support/pip/pip.conf"),
        Path("/opt/homebrew/etc/npmrc"), Path("/usr/local/etc/npmrc"),
    )
    for path in files:
        profile += f" (deny file-read* (literal {json.dumps(str(path))}))"
    profile += (
        f" (deny file-read* (require-all (subpath {workspace})"
        ' (regex #".*/([^/]*[.]env([.]|$)|[.]npmrc$|pip[.]conf$|'
        '(secrets|credentials|wallet)(/|$)|[^/]*[.](key|wallet)$)")))'
    )
    return profile


def added_line_scan() -> int:
    """Keep scanner output private and expose each distinct file and line only."""
    locations: set[tuple[str, int]] = set()
    for options in (
        ["--log-opts=origin/main..HEAD --diff-merges=first-parent"],
        ["--pre-commit", "--staged"],
        ["--pre-commit"],
    ):
        try:
            result = subprocess.run(
                [
                    "gitleaks", "git", "--redact=100", "--no-banner", "--exit-code", "42",
                    "--report-format", "json", "--report-path", "-", *options, ".",
                ],
                cwd=ROOT,
                capture_output=True,
                check=False,
                timeout=90,
            )
            findings = json.loads(result.stdout)
            if result.returncode not in (0, 42) or not isinstance(findings, list):
                raise ValueError
            if bool(findings) != (result.returncode == 42):
                raise ValueError
            for finding in findings:
                path = finding["File"]
                line = finding["StartLine"]
                if not isinstance(path, str) or not path or type(line) is not int or line < 1:
                    raise ValueError
                locations.add((path, line))
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            print("added-line scan unavailable")
            return 1
    for path, line in sorted(locations):
        print(f"{json.dumps(path, ensure_ascii=True)[1:-1]}:{line}")
    print(f"added-line findings: {len(locations)}")
    return int(bool(locations))


def run_commands(
    commands: Sequence[Sequence[str]],
    output: Path | str,
    *,
    network_policy: str = "deny",
) -> list[dict[str, object]]:
    """Execute argv commands under macOS sandbox-exec and retain every exit code."""
    sandbox = "/usr/bin/sandbox-exec"
    if platform.system() != "Darwin" or not os.access(sandbox, os.X_OK):
        raise RuntimeError("macOS sandbox-exec required; refusing unisolated execution")
    if network_policy not in ("deny", "outbound-permitted"):
        raise ValueError("Unsupported network policy")
    audit = network_policy == "outbound-permitted"
    profile = (
        _audit_profile(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve())
        if audit else SANDBOX_DENY_NET
    )

    output_dir = Path(output)
    _private_directory(output_dir)

    repo_bins = _designated_venv_bins(ROOT)
    current_bin = Path(sys.executable).absolute().parent
    prefix_bins = [str(p) for p in repo_bins] if repo_bins else [str(current_bin)]

    results: list[dict[str, object]] = []
    # macOS Unix socket paths are short. Keep TFLint's private TMPDIR under /private/tmp.
    with tempfile.TemporaryDirectory(prefix="crm-ci-", dir="/private/tmp") as home:
        temp = Path(home) / "tmp"
        temp.mkdir(mode=0o700)
        env: dict[str, str] = {}
        for key in SAFE_ENV_KEYS:
            if key in os.environ:
                env[key] = os.environ[key]
        existing_path = env["PATH"] if "PATH" in env else os.defpath
        env.update(
            HOME=home,
            PATH=os.pathsep.join([*prefix_bins, str(ROOT / ".gate/bin"), existing_path]),
            TMPDIR=str(temp),
            OCI_AUTH_MODE="config",
            OCI_CONFIG_FILE="/dev/null",
            PIP_CONFIG_FILE="/dev/null",
            PIP_NO_CACHE_DIR="1",
            PYTHONDONTWRITEBYTECODE="1",
            PYTHONNOUSERSITE="1",
            PYTHONPATH=str(ROOT),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL="/dev/null",
        )
        if audit:
            for key, name in (
                ("PIP_CONFIG_FILE", "pip.conf"),
                ("NPM_CONFIG_USERCONFIG", "npm-user.conf"),
                ("NPM_CONFIG_GLOBALCONFIG", "npm-global.conf"),
            ):
                config = Path(home) / name
                with _open_private_write(config):
                    pass
                env[key] = str(config)
            env.pop("PYTHONPATH")
            env["PYTHONSAFEPATH"] = "1"
            env["PIP_KEYRING_PROVIDER"] = "disabled"
        for index, raw_command in enumerate(commands):
            command = [str(part) for part in raw_command]
            log = output_dir / f"{index:02d}.log"
            with _open_private_write(log) as stream:
                resolved = _resolve_executable(command[0], repo_bins, env["PATH"])
                if resolved is None:
                    stream.write(f"Local command unavailable: {command[0]}\n")
                    code = 127
                else:
                    command_profile = profile
                    if not audit and command[0] == "tflint":
                        socket = f'unix-socket (regex #"^{re.escape(str(temp))}/")'
                        command_profile += (
                            f" (allow network-bind network-inbound (local {socket}))"
                            f" (allow network-outbound (remote {socket}))"
                        )
                    try:
                        proc = subprocess.run(
                            ["/usr/bin/sandbox-exec", "-p", command_profile, resolved, *command[1:]],
                            cwd=ROOT,
                            env=env,
                            stdout=stream,
                            stderr=subprocess.STDOUT,
                            timeout=600 if audit else 300,
                            check=False,
                            umask=0o077,
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
    name: str, spec: JobSpec, *, allow_online: bool
) -> tuple[bool, str, str | None, str]:
    if name == "node-audit" and (
        not (ROOT / "package.json").is_file()
        or not any((ROOT / lockfile).is_file() for lockfile in ("package-lock.json", "npm-shrinkwrap.json"))
    ):
        return False, "deny", "Missing package.json or npm lockfile.", "deny"
    if spec.requires_online:
        if not allow_online:
            return False, "deny", UNAVAILABLE_OFFLINE_AUDIT_REASON, "deny"
        return True, ONLINE_NETWORK_LABEL, None, "outbound-permitted"
    return True, "deny", None, "deny"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--added-line-scan", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--allow-online", action="store_true")
    parser.add_argument("--job", choices=tuple(JOBS), action="append")
    parser.add_argument(
        "--receipt",
        type=Path,
        default=ROOT / OUTPUT / "receipt.json",
    )
    args = parser.parse_args(argv)

    if args.added_line_scan:
        return added_line_scan()
    if args.list:
        listing: dict[str, dict[str, object]] = {}
        for name, spec in JOBS.items():
            available, network_label, reason, _ = _effective_job_state(
                name, spec, allow_online=args.allow_online
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
    _private_directory(output_root)

    records: dict[str, dict[str, object]] = {}
    selected_jobs = args.job or list(JOBS)
    for job_name in selected_jobs:
        spec = JOBS[job_name]
        available, network_label, reason, network_policy = _effective_job_state(
            job_name, spec, allow_online=args.allow_online
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
            except (RuntimeError, OSError, ValueError) as error:
                record = {
                    "status": "unavailable",
                    "network": network_label,
                    "workflow": spec.workflow,
                    "reason": str(error),
                    "commands": [],
                }
        records[job_name] = record
        detail = f" ({record['reason']})" if "reason" in record else ""
        print(f"{job_name}: {record['status']}{detail}", flush=True)

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
    _private_directory(args.receipt.parent)
    with _open_private_write(args.receipt) as receipt_stream:
        receipt_stream.write(json.dumps(receipt, indent=2) + "\n")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
