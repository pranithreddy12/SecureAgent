# SecureAgent – Testing

Status as of 2026-10-09: **253 backend tests: 252 pass, 1 skipped, 0 fail** (the skipped PDF test needs
the Pango libraries and passes in the Docker image), **93% line coverage** of `backend/app`.
The frontend has **no automated tests yet** (see *Gaps*).

## Running the tests

```bash
make testdb                 # one-time: throwaway PostgreSQL on localhost:55432 (needs Docker)
cd backend
python -m pytest -q         # whole suite (DB-backed tests included)
python -m pytest -q --ignore=tests/test_models.py --ignore=tests/test_auth.py   # no Docker needed
```

Pure static-analysis tests never touch the network or a database. The OSV client is tested
through an injected fake transport; a live OSV query is only made by the CLI and was verified
manually (see `PROJECT_MEMORY.md`).

The PDF test needs WeasyPrint's native libraries, which are present in the backend Docker
image but not on a typical Windows host:

```bash
docker compose run --rm --no-deps backend python -m pytest tests/test_reports.py
```

Quality gates (also run in CI): `ruff check`, `ruff format --check`, and for the frontend
`npm run lint`, `npx tsc --noEmit`, `npm run build`.

## What is tested, by area

| Area | Tests | Files |
|---|---|---|
| Database schema & constraints (real PostgreSQL, built by the real Alembic migration) | 10 | `test_models.py` |
| Authentication (hashing, cookie/Bearer, forged/expired/`alg=none` tokens, enumeration resistance, role-injection ignored) | 18 | `test_auth.py` |
| Health / configuration parsing | 2 | `test_health.py` |
| Secret detection, redaction, ingestion limits, CLI | 10 | `test_secret_scan.py` |
| Dependency parsing + OSV mapping (fake transport), lockfile ingestion regression | 12 | `test_dependencies.py` |
| Dangerous sinks (deserialization, exec, weak crypto, TLS, XXE) | 14 | `test_sinks.py` |
| Taint: single-function, deep (interprocedural + JS), cross-file, return-value | 12 + 11 + 6 + 7 | `test_taint*.py` |
| IDOR / object-level authorization | 10 | `test_access_control.py` |
| Security misconfiguration | 13 | `test_misconfig.py` |
| Logging & monitoring (A09) | 8 | `test_logging.py` |
| Routes & authorization (FastAPI/Flask/Express) and Django/NestJS frameworks | 11 + 12 + 14 | `test_route_scan.py`, `test_frameworks.py`, `test_django_depth.py` |
| Baseline & CI gating | 10 | `test_baseline.py` |
| SARIF 2.1.0 output | 7 | `test_sarif.py` |
| Suppression (`--exclude`, `.secureagentignore`, inline ignore) and secret false-positive fixes | 25 | `test_suppression.py` |
| Report generation (19 sections, escaping, honest CVE/CVSS) | 8 | `test_reports.py` |
| `.env.example` stays in sync with the settings class; placeholders only | 3 | `test_env_contract.py` |
| Installed CLI works without the web stack (SQLAlchemy/FastAPI imports poisoned) | 4 | `test_cli_standalone.py` |
| Report polish (risk rating, grouping, priorities, compact sections) | 16 | `test_report_polish.py` |
| Demo pack (expected findings, clean safe file, labelling, redaction, exclusion from ordinary scans) | 10 | `test_demo.py` |

## Security-restriction tests

The brief requires every important security restriction to be tested. Covered today:

- Passwords are never stored or returned in plaintext; login failures are indistinguishable
  (same status and message for unknown email vs wrong password).
- Invalid tokens are rejected: garbage, expired, signed with the wrong key, unknown user,
  deleted user, and `alg=none`.
- A registration request cannot grant itself the admin role.
- Secret values never appear in findings, console output, JSON or reports (only a masked preview
  and a fingerprint).
- Reports escape untrusted text (a finding containing HTML cannot inject markup).
- CVE and CVSS are never invented ("Not applicable…", "CVSS not determined." unless supplied).
- Static analysis never reports a finding as `confirmed`.
- Suppression is never silent: excluded files and inline-ignored findings are counted in text
  and JSON output.
- The scanner is read-only and bounded (file/size limits; vendored/VCS/binary skipped).

**Not testable yet** because the code does not exist: target safety validation (private,
loopback, link-local and cloud-metadata blocking, allowlists, scope), the authorization gate on
audits, and tool-level scope enforcement. These depend on target management, which is blocked
for the assistant — see `docs/target-management-implementation.md`, which lists the required
tests.

## Honesty about what the tests prove

- Detector tests use small, hand-written snippets plus a bundled demo application
  (`secureagent demo`) whose expected findings are pinned. They show the detectors do what they
  are designed to do on known patterns; they are **not** a measured detection rate on real-world
  code, and no false-positive/false-negative benchmark against a public corpus has been run.
- The dogfood scan (SecureAgent scanning this repository) is part of the evidence: it found and
  led to fixing two false positives, a `.lock` ingestion bug, and unpinned dependencies.

## Gaps (also tracked in `docs/PROJECT_CLOSEOUT.md`)

1. **Frontend** — 0 tests. Lint, type-check and build pass; behaviour was verified manually in a
   browser (login, register, redirects, sign-out).
2. **End-to-end** — no automated browser or full-stack test.
3. **Audit pipeline** — agents, LangGraph workflow, ZAP and Nuclei integrations do not exist, so
   have no tests.
4. **Coverage** — lowest files: `schemas/target.py` (0%, awaiting the blocked endpoints),
   `core/database.py` (69%), `analysis/dependencies.py` (78%), `analysis/osv.py` (84%; the
   network path is intentionally not unit-tested).
