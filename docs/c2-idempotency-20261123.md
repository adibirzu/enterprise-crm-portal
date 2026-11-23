# C2 order creation idempotency, 2026-11-23

Goal: make order creation retry-safe under the published CRM contract.
Branch: `adibirzu/c2-crm-idempotency`.
Base: fetched live `origin/main`, `39cf05a412a41d54b62f1d35dea6d9aa9552df3e`.
Evidence class: **locally verified**, with code-backed contract changes.
Provider verification and release acceptance remain **unverified**.

## Change and persistence contract

The existing `(source_system, source_order_id)` unique constraint remains the
persistence key. A lookup precedes customer/product resolution, so retries
return the original response even after a catalog price change. The existing
`source_payload` Text column stores a canonical JSON request snapshot including
the optional token. A different snapshot for the same reference returns 409.
A uniqueness failure at flush or commit rolls back through `get_db`; a fresh
session reads the winner and applies the same replay/conflict decision.
An unrelated integrity failure propagates, with rollback and no creation metric.
Manual requests without a source order ID continue creating separate orders.

No database migration exists or is required by this implementation. No real or
shared database was accessed. Historical rows without the new request snapshot
return 409 rather than claiming payload equality. Token-only deduplication is
not provided; stable source references are required. Numeric representation and
item order are part of request equality, as documented in the served contract.

## Test-first evidence

The separate RED commit is `f037f6f`.
Before production changes, the new suite reported `13 failed, 1 passed` with
exit 1. Duplicate requests returned 500 and changed requests did not return 409.
After implementation, the original focused suites reported `18 passed`, exit 0.
Review expanded the new suite to 21 cases covering ordinary replay, real SQLite
unique failures at flush and commit, payload conflicts, changed catalog prices,
source scoping, manual order independence, missing tokens, default source,
fractional prices, legacy snapshots, and unrelated uniqueness rollback.
Tests assert response bodies, row counts and creation metric cardinality.

The SQLite adapter uses real SQLAlchemy sessions and a disposable local file.
It deterministically hides the first lookup to model a competing transaction
winning an insert. These are isolated transaction/uniqueness tests, not a real
parallel PostgreSQL or Oracle execution or production concurrency acceptance.

## Environment and gates

The coordinator explicitly authorized a workspace-only `.venv` installed from
`requirements.txt`. All 30 direct requirements satisfy their declared pins or
ranges; `pip check` exits 0. The manifest has ranges and transitive dependencies,
so this is not a fully locked dependency environment. No tools were installed.
The test entry point uses `.venv/bin/python` and appends the preinstalled Python
site-packages path for existing pytest tooling; runtime direct dependency
versions come from `.venv`. This is pinned-runtime evidence, not a hermetic test
tooling environment. Earlier RED and focused GREEN runs used system Python.

Private, untracked command receipts and logs are under `.state/c2/`; the runner
removes database credentials/endpoints and disables dotenv loading. TestClient
probes do not start application lifespan or database bootstrap.

| Check | Exit | Result |
| --- | --- | --- |
| Full suite, pinned runtime | 0 | 78 passed, no skips |
| Health/frontend smoke, pinned runtime | 0 | 14 passed, no skips |
| Full-app consumer schema/protected-route probe | 0 | C1 probe reused read-only, pinned runtime |
| Direct requirement version check | 0 | 30 requirements, no mismatches |
| `.venv/bin/python -m pip check` | 0 | No broken requirements |
| `pip-audit -r requirements.txt --strict` | 1 | 21 advisory rows across 6 packages, including duplicates |
| `bandit -q -r server -x server/__pycache__ -ll -iii` | 1 | Existing baseline findings |
| `ruff check --select S server` | 1 | 29 existing baseline findings |
| `mkdocs build --strict` | 0 | Output redirected to private workspace receipts |
| `gitleaks detect --source . --redact` | 1 | Existing historical synthetic UUID example |
| `cyclonedx-py requirements requirements.txt --spec-version 1.6 -o <receipt>` | 127 | Tool unavailable; not installed |
| Scoped production/new-test F821,F401 lint | 0 | Passed |
| Existing auth-test F821,F401 lint | 1 | Pre-existing unused asyncio import |
| Staged/new-commit gitleaks | 0 | Clean scoped change |

The CycloneDX command was unavailable before argument parsing; no BOM is claimed.
No findings or exit codes were suppressed. Gate C as a whole remains failed on
baseline security checks and unavailable SBOM tooling, as in the C1 report.
The historical synthetic token example was unchanged; there is no confirmed
real credential finding. Scoped scans establish cleanliness only for this change.

## Independent review and remaining work

Installed Claude CLI reviewed the scoped diff on stdin with `--safe-mode`,
`--tools ""`, `--strict-mcp-config`, an empty MCP configuration and no session
persistence. No helper agents were started. Initial review exited 0 and led to
additional coverage and precise contract wording. The final review exited 0,
reported `claude-opus-5-5`, and concluded `NO FINDINGS` with no blocking defects.
Conditional fixed-scale numeric concerns were rejected against the Float model
and fractional SQLite coverage; real-provider numeric behavior is unverified.
The reviewer noted pre-existing invalid non-string source-reference input
handling as non-blocking. No production change was needed after initial review.

No push, PR, merge, deploy, cloud API call or shared database mutation occurred.
Free disk stayed above 10 GiB; no additional installs followed the disk warning.
Resolve baseline security/SBOM gates and obtain separate provider/release
acceptance before any promotion. Normal commit hooks report missing lefthook;
explicit scans and test runs above are independent evidence, not hook acceptance.
