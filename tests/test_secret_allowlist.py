"""The documentation example exemption cannot suppress other paths or values."""
from pathlib import Path
import subprocess

import pytest


EXAMPLE = "-".join(("5e1a6db6", "8c0e", "5f1c", "9c9a", "3b0c2a1f0f01"))
TARGET = "docs-site/integrations/cross-service-contract.md"


@pytest.mark.parametrize("path,value,expected", [
    (TARGET, EXAMPLE, 0),
    ("other.md", EXAMPLE, 1),
    (TARGET, EXAMPLE[:-1] + "2", 1),
])
def test_only_exact_documentation_example_is_allowed(tmp_path, path, value, expected):
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("  \"idempotency_token\": \"" + value + "\"\n")
    command = ["gitleaks", "dir", ".", "--redact", "--no-banner"]
    config = Path.cwd() / ".gitleaks.toml"
    if config.exists():
        command += ["--config", str(config)]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == expected, result.stderr
