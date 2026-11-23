# C3 CRM security gates, 2026-11-23

Goal: clear code-owned gate C findings while preserving CRM behavior and
reporting environment limitations separately.

Branch: `adibirzu/c3-crm-security-gates`.
Base: freshly fetched `origin/main`, `39cf05a412a41d54b62f1d35dea6d9aa9552df3e`.
The separate C2 branch remains at `489e639`; C2 was not cherry-picked into C3.
Evidence is **locally verified** and **code-backed**, not provider verified or
release accepted. No push, PR, OCI/provider call, shared database access or deployment occurred.
External requests were limited to package-index/advisory queries and the
explicitly requested Claude review.

## Dependency changes

The original audit reported duplicate advisory rows across six packages. Changes
use the minimum advisory-clearing versions, with coordinator-approved coupled
upgrades and a replacement where no fixed release exists.

| Change | Before | After | Reason |
| --- | --- | --- | --- |
| OTel API / SDK / HTTP exporter | 1.41.0 | 1.45.2 | Fixed API; SDK pins the API exactly |
| OTel instrumentation / Prometheus exporter | 0.62b0 | 0.66b2 | Exact semantic-convention compatibility with SDK 1.45.2 |
| OCI SDK | 2.172.0 | 2.184.1 | First checked newer release admitting cryptography 50 |
| cryptography | resolved 46.0.7 | exact 50.0.0 | Minimum version clearing all reported advisories |
| python-multipart | 0.0.26 | 0.0.31 | Minimum version clearing all reported advisories |
| pydantic-settings | 2.14.0 | 2.14.2 | Minimum fixed release |
| JWT backend | python-jose 3.5.0 | PyJWT[crypto] 2.15.1 | python-jose and mandatory ecdsa have no fixed release |

Package-index metadata showed OCI 2.184.0 still excludes cryptography 50;
2.184.1 admits it. The resolver also updated required transitive OpenSSL support
and installed crc32c. Unrelated direct pins were retained. The old jose, ecdsa,
rsa and pyasn1 packages were removed from this workspace venv after replacement;
`pip check` passes. Dependencies were installed only in the reused workspace
`.venv`, with `--no-cache-dir`, after checking free disk above 10 GiB.

## Test-first behavior and security decisions

Offline OIDC tests use generated RSA keys and stub discovery/JWKS retrieval.
They cover RS256/RS384/RS512 signature verification, selection by kid, wrong
signature, expiry, audience, issuer, nonce, not-before, key rotation, unknown kid,
malformed tokens, unsigned tokens, and HMAC confusion using a public DER key.
Before replacement, disabling the jose import produced `1 failed, 14 passed`.
After replacement, all 15 passed. Two issued-at compatibility tests then exposed
a library-default difference (`1 failed, 16 passed`); the fix retains the old
numeric-only issued-at policy, and all 17 now pass. Algorithm allowlisting,
issuer/audience verification, expiry/not-before checks and nonce checks remain.
The coordinator explicitly approved one intentional tightening after review:
when an audience is configured, missing or empty `aud` is rejected. The previous
python-jose verifier accepted a missing audience claim. Three regression cases
cover missing/empty-string/empty-list `aud`; a positive audience-list case
contains the configured client. Other claim-policy behavior remains as described
above; malformed issued-at types now fail closed rather than escaping as errors.

Two non-security MD5 paths failed under a simulated FIPS restriction before the
change (`2 failed`) and pass afterward (`2 passed`). They now explicitly pass
`usedforsecurity=False`. Golden assertions preserve existing Oracle SQL IDs and
synced-product SKUs; no hash migration or persistence migration is needed.

All 27 other Ruff findings have specific per-site exceptions with nearby reasons:

- Deliberate SQL injection, predictable-key, SSTI, deserialization and shell-export
  demo sites retain their attack-telemetry behavior. The four overlapping Bandit
  demo sites use specific B324/B701/B301/B602 exceptions.
- Chaos/synthetic-data randomness does not generate credentials or access grants.
- Campaign update fragments use fixed column literals and bound request values.
- Optional tracing, session tagging, metrics and log-export failures remain
  non-fatal. The log exporter avoids recursively logging its own failure.

No blanket scanner disable was added. Bandit can print no-matching-test warnings
for multiple AST nodes sharing a specifically suppressed line; its exit is 0.
The demo routes remain deliberately unsafe. A clean scanner result here does
not establish production suitability or remove the demo attack surfaces.

The gitleaks exception extends default rules and adds a `generic-api-key`
rule-specific allowlist with AND semantics for the exact contract path and exact
synthetic UUID line. Tests prove the same value elsewhere and another value in
the same document still fail. Initial default scanning gave `1 failed, 2 passed`;
a global-allowlist attempt was rejected by the negative test because the tool
skipped the document, and the final rule-specific version passes all three.
No historical content was rewritten and no other finding was accepted.

## Gate receipts by commit

The full suite and gate C commands ran after every implementation commit.
Private detailed logs and exact argv/exit receipts are under `.state/c3/<phase>/`.

| Commit / phase | Tests | Requirements audit | Bandit | Ruff S | History gitleaks | Resolved SBOM audit |
| --- | --- | --- | --- | --- | --- | --- |
| 3857899 / otel | 57 pass | 1 | 1 | 1 | 1 | 1 |
| 159e5d5 / oci | 57 pass | 1 | 1 | 1 | 1 | 1 |
| 17bf3bb / jwt | 72 pass | 1 | 1 | 1 | 1 | 1 |
| 0b2662d / parser-settings | 72 pass | 0 | 1 | 1 | 1 | 1 |
| 5156f16 / scanners | 74 pass | 0 | 0 | 0 | 1 | 1 |
| df95f94 / allowlist | 77 pass | 0 | 0 | 0 | 0 | 1 |
| 249d244 / jwt-policy | 79 pass | 0 | 0 | 0 | 0 | 1 |
| Final audience handoff | 83 pass | 0 | 0 | 0 | 0 | 1 |

The final audience handoff adds four approved audience cases, for 83 tests in
total. Each row also has full-suite exit 0, health/frontend smoke exit 0 (14 passed),
`pip check` exit 0, and strict MkDocs build exit 0. No test skips were reported.
The two full-suite warnings are existing FastAPI TestClient and crypt deprecations.

Final gate commands use the following arguments; no failing exit is masked:

- Full suite through `.venv/bin/python`, invoking preinstalled pytest tooling.
- `pip-audit -r requirements.txt --strict`
- `bandit -q -r server -x server/__pycache__ -ll -iii`
- `ruff check --select S server`
- `gitleaks detect --source . --redact`
- `mkdocs build --strict --site-dir <private-workspace-output>`
- `pip-audit --path .venv/lib/python3.11/site-packages --strict --format cyclonedx-json --output docs/security/c3-resolved-20261123.cdx.json`

All code/runtime-requirements gates now exit 0. The resolved-environment SBOM
audit still exits 1 for the build-tool advisory described below. It produced a
valid inventory; exit 1 is retained, not represented as a clean environment audit.
Normal Git hooks report missing lefthook; the explicit checks above are separate
evidence and do not claim successful hook enforcement.

## Resolved SBOM and environment limits

The generated [resolved inventory](security/c3-resolved-20261123.cdx.json) is
CycloneDX 1.4 from installed distributions, not a re-resolved requirements list.
All 77 distributions in `.venv` appear with matching versions, including all
31 direct requirements (packaging included). No installed component is missing or extra.
The inventory contains flat component references; it does not attest complete
package dependency edges, images, OS packages, deployment state or runtime loading.

The auditor reports GHSA-xmj3-9gf7-h52w against workspace build tool
`setuptools==84.0.0`. This package is not a runtime requirement in the repository.
Its advisory concerns a legacy Windows wheel-installation path. It remains visible
in the inventory and audit, with no ignored vulnerability or unauthorized tooling
upgrade. This environment-only finding needs a separate build-tool decision.

The reused venv satisfies all 31 declared runtime requirements. Existing pytest
tooling is accessed by appending the preinstalled Python site-packages path in
the test entry point, so tests are not a hermetic development-tool installation.
No new test/audit tools were installed. The allowlist regression also requires
the installed gitleaks CLI (tested 8.30.1) and repository-root working directory. Dotenv loading and service credentials /
endpoints are disabled for tests; TestClient does not start database bootstrap.
No live IdP, OCI, Oracle or PostgreSQL validation is claimed. The full-app
consumer schema/protected-route probe exits 0 and initializes the Prometheus
reader. Configured OTLP exporter initialization/export and independent backend
readback remain unverified. No DB migration exists.

## Review and remaining work

Claude CLI review completed with exit 0 using `claude-opus-5-5`, safe mode,
empty built-in tools, empty strict MCP configuration and no session persistence.
It found no code blockers. Its required report correction identified the audience
policy tightening, which the coordinator approved explicitly before finalization.
The report now records that exception and the added audience regression coverage.
Optional review notes about CLI requirements, build-tooling isolation, exporter
coverage, package/advisory access and SBOM relationship limits are recorded above.
`git grep -n jose -- server requirements.txt tests` found only three test
references: the negative-import test name, its explicit disabled-module fixture,
and the prior-policy compatibility test name. Runtime source and requirements
have no remaining jose references. The receipt is `.state/c3/jose-references.log`.

## Live acceptance requirement before release

Live identity-provider audience evidence is **unverified** for every deployment
client. This task did not enumerate private client configuration or inspect real
tokens. There is one product configuration input, `IDCS_CLIENT_ID`; deployments
may configure different clients. No per-client audience success is claimed.

| Acceptance target | Current evidence | Required live acceptance check |
| --- | --- | --- |
| Each deployment client configured through IDCS_CLIENT_ID | Unverified; only generated local fixtures exercised | Verify a normally issued ID token after trusted signature/issuer validation contains non-empty aud with that configured client ID |
| Each configured client using array-valued aud | Unverified; local positive-array fixture passes | Confirm the configured client ID is present in the issued audience array |
| Missing or empty aud | Locally verified rejection only | Confirm rejection in the target deployment, without retaining full tokens |

The live acceptance package must record one sanitized result per configured client
with environment/client alias, audience present yes/no, configured audience match
yes/no, verification time, and pass/fail. Do not store full tokens, real client IDs
or credentials in shared artifacts. A missing/empty/mismatched audience blocks
release acceptance until the client configuration is corrected or separately ruled.
The intentional tightening must appear in any later PR description.

The implementation remains local only. The environment-only setuptools advisory,
hermetic test tooling, configured exporter verification and provider/release
acceptance remain separately scoped.
