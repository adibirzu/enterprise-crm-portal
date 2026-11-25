# Local CI gate

Use macOS with Seatbelt and Python 3.11. Install the CRM dependencies from
`requirements.txt` plus pytest, pytest-asyncio, Bandit, pip-audit, Ruff, Semgrep,
MkDocs, mkdocs-material, and pymdown-extensions in `.gate/venv`. Make Git,
Gitleaks 8.30+, Node.js/npm, Terraform 1.7.5, TFLint, and Trivy available on
`PATH` or in `.gate/bin`.

Before running the gate, provision the Semgrep Registry YAML packs
`p/owasp-top-ten`, `p/python`, and `p/fastapi` in `.gate/semgrep-rules/` as
`owasp-top-ten.yml`, `python.yml`, and `fastapi.yml`. Use Trivy with bundled
configuration checks. The gate invokes installed tools and uses the local rule
packs.

```sh
.gate/venv/bin/python scripts/local_ci_gate.py --list --allow-online
.gate/venv/bin/python scripts/local_ci_gate.py --allow-online
```

| GitHub workflow job | Local job | Coverage |
| --- | --- | --- |
| `security-gates / python-sast` | `python-sast`, `dependency-audit` | Bandit and Ruff security rules on `server`, offline Semgrep with the three named packs, and strict pip-audit against `requirements.txt`. |
| `security-gates / node-audit` | `node-audit` | Production npm advisory check at high severity using the lockfile with scripts disabled. Without a manifest and lockfile, the check is unavailable and the aggregate fails. |
| `security-gates / secret-scan` | `secret-scan` | Gitleaks scans additions in commits ahead of `origin/main`, the index, and tracked working-tree edits. It prints unique file and line locations and a count. Stage new files to include them. |
| `security-gates / terraform-lint` | `terraform-lint` | Recursive Terraform format check, TFLint initialization, and recursive TFLint. The two directory-based checks fail while `deploy/terraform` is absent. |
| `security-gates / container-scan` | `container-scan` | Trivy scans the repository's configuration at HIGH and CRITICAL severity. The local gate fails on findings. |
| `mkdocs-deploy / build-and-deploy` | `mkdocs-build` | Strict offline build. The receipt names GitHub Pages publication as an omitted hosted operation. |
| Additional local checks | `unit-tests`, `smoke-tests` | Full pytest suite and focused health and frontend checks. |

Only pip-audit and npm audit can use HTTPS and system DNS, after
`--allow-online` opts in. They use a temporary home with distinct empty
mode-0600 pip and npm configuration files and restricted access to workspace
and host credential paths. TFLint can use Unix sockets under its private
temporary directory for the bundled plugin. All other gate checks run with
networking denied.

No Mistakes uses the aggregate with the isolated dependency audits for testing
and the offline checks for linting. Logs and the receipt live privately under
`.gate/local-ci/`. Missing tooling, unavailable required checks, and nonzero
command exits fail the aggregate.
