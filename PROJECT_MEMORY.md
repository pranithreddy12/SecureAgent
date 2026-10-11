# SecureAgent Project Memory

> Read this first in every session, then verify against the actual repository.
> Current state lives here; history lives in `PROJECT_CHANGELOG.md`; the original
> baseline lives in `SPECIFICATION.md`. Never store secrets in this file.

Last updated: 2026-10-11 (final close-out; see docs/PROJECT_CLOSEOUT.md)

## 1. Project Identity

- **Name:** SecureAgent – Multi-Agent AI Application Security Auditor
- **Type:** Major academic project / working security platform
- **Purpose:** Audit *authorized* web apps/APIs with AI agents + deterministic tools
  (ZAP, Nuclei); safe validation, false-positive reduction, standards mapping, reports.
- **Owner email (attribution only):** see git config.

## 2. Original Scope

See `SPECIFICATION.md`. Important: the PPT was **not provided** at Phase 0; the owner
chose to use their written brief as the baseline. PPT-only sections (abstract text,
existing system, hardware requirements, PPT references) are marked PENDING. When the
PPT arrives: fill PENDING sections only and log any conflicts in §16.

## 3. Current Scope
### Implemented

**Static-analysis engine + CLI** (`backend/app/analysis/`, `backend/app/cli.py`; full detail in
`docs/static-analysis.md`, history in `PROJECT_CHANGELOG.md`)
- Read-only ingestion with limits; `--exclude` / `.secureagentignore`; inline `secureagent: ignore`
  (all suppression is counted in the output, never silent).
- Detectors: hardcoded secrets (redacted); dependencies + OSV (requirements*/Pipfile.lock/poetry.lock/
  package-lock.json); dangerous sinks; taint (within function, within file, **cross-file**,
  **return-value**, JS/TS heuristic); IDOR; misconfiguration (Flask/FastAPI/Django); logging (A09);
  route + authorization extraction (FastAPI, Flask, Express, Django/DRF incl. class-based views, NestJS).
- Output: text, JSON, SARIF 2.1.0, HTML, PDF; baseline (`--baseline`, `--write-baseline`) and
  `--fail-on` CI gating; `secureagent demo` (bundled deliberately vulnerable sample + a safe-code file).
- Installable `secureagent` command needing only jinja2 + pydantic (`pdf` extra for WeasyPrint);
  guarded by `tests/test_cli_standalone.py` (runs with SQLAlchemy/FastAPI imports poisoned).
- Honesty model: static findings are never `confirmed`; heuristic ones are `suspicious`; CVE only from
  real advisories; CVSS only when supplied (currently never populated for OSV findings).

**Business logic + integrations (2026-10-10/11)**: client-trusted value / mass-assignment detectors and the
JSON intent spec (ADR-010), authorization matrix (`scan --matrix`), accuracy benchmark
(`secureagent benchmark`, `docs/benchmark.md`), MCP server (`secureagent-mcp`, `docs/mcp.md`).

**Verified fix patches (2026-10-11, ADR-013)**: `secureagent fix PATH [--apply]`, MCP `suggest_fixes`;
weak hash, TLS/JWT verification, yaml.load, debug/CSRF flags, hardcoded Python secrets. Verified = parses +
re-scan shows finding gone and nothing new; never writes unverified or stale files. Demo: 34 -> 26 findings.

**Attack chains (2026-10-11, ADR-012)**: `app/analysis/chains.py`; shown in CLI/JSON/MCP, report section 8
and the audit page (`attack_chains` on `GET /api/audits/{id}`, stored in `stage_state`). Severity = worst
member (never escalated); chains are not findings and are excluded from baselines/gating.

**Persisted source audits (2026-10-11, ADR-011)**: `/api/audits/*` (create with authorization confirmation,
list, detail, findings, logs, report HTML/PDF), asyncio runner (`services/audit_service.py`), path
confinement to `SOURCE_ROOTS` (`core/paths.py`), migration `b7c1d2e3f4a5` (nullable `target_id`,
`audit_type`), frontend `/audits` + `/audits/[id]` (polling progress, findings, logs, report links),
dashboard shows real counts. Verified end to end through Docker (register -> audit -> 31 findings -> PDF).

**Reporting** (`app/schemas/report.py`, `app/reports/`, `app/analysis/reporting.py`): 19-section
HTML/PDF report with table of contents, risk rating, "Fix first" priorities, hotspots, findings
consolidated by type, grouped remediation, compact CVE/CVSS sections; DEMO labelling.

**Web app (skeleton)**: FastAPI app factory + settings; Argon2id/JWT-cookie authentication
(`/api/auth/*`, ADR-006); 8 SQLAlchemy models + Alembic migration `afb3ff51caae`; Next.js 16 frontend
(login, register, dashboard shell with live health, settings, route protection); Docker Compose
(postgres, zap, backend, frontend, `lab` juice-shop); backend image pinned to `requirements.lock`.

**Project infrastructure**: SPECIFICATION (PPT sections still PENDING), memory, changelog, 8 ADRs,
traceability, 7 validated UML diagrams, docs (architecture, agent-workflow, security-model, database, api,
static-analysis, business-logic-engine, testing, deployment, demo-guide, closeout), README, repo CI
workflow (`.github/workflows/ci.yml`, four jobs, green), GitHub Action example.

### In Progress
- Nothing. The 2026-10-11 final close-out is complete; see `docs/PROJECT_CLOSEOUT.md`.

### Deferred by decision (ADR-014, 2026-10-11) -- was "Blocked"
- **Phases 4-5 (target management, network-safety validation, authorization)** — the generation of
  `backend/app/security/target_validation.py` and `backend/app/services/target_service.py` was stopped
  twice by an automated safety classifier; the assistant may not regenerate that content. Requirements
  are unchanged. Hand-off spec: `docs/target-management-implementation.md`; the schemas
  (`app/schemas/target.py`) are committed. Once the owner supplies the two files the assistant can
  build the authorization service, `/api/targets` endpoints, frontend pages and tests around them.
- Phases 6-12 and 15 (reconnaissance, ZAP, Nuclei, safe validation, validator, report agent, LangGraph
  workflow, audit runner, progress) depend on targets/authorization; **not started**.

### Planned
- Everything blocked above; targets/global findings/reports/activity pages; live-audit structured logging;
  optional LLM reasoning. (Frontend tests, e2e, login throttling and admin bootstrap are done.)
- Grey-box business-logic engine beyond what exists (ADR-008/010/012/013): a UI/API for the developer-intent
  input (the JSON spec + CLI flag exist), Application Model persistence, JS/TS logic detectors.

### Deferred
- Continuous / scheduled audits and CI/CD-triggered audits (architecture is extensible only).

### Removed
- None.

## 4. Current Architecture

Designed (not yet coded): Next.js frontend → FastAPI backend (api → services →
models; LangGraph workflow → agents → tools) → PostgreSQL; ZAP daemon container;
Nuclei binary inside backend image; optional LLM via LangChain.
Details: `docs/architecture.md`.

## 5. Agent Architecture

ReconnaissanceAgent, VulnerabilityScannerAgent, SafeValidationAgent (= PPT
"Exploitation Agent", ADR-003), ValidatorAgent, ReportAgent.
Added by the grey-box scope change (ADR-008, designed, not built): **Code
Intelligence Agent** (static source analysis → Application Model) and
**Business-Logic Reasoning Agent** (logic-flaw candidates from the model + dev
description + recon). Details: `docs/agent-workflow.md` §4 and
`docs/business-logic-engine.md`.

## 6. LangGraph Workflow

authorization_check → target_validation → reconnaissance → attack_surface_processing
→ vulnerability_scanning → (findings? safe_validation → validator) → report_generation
→ persist_results. Gate nodes fatal; tool nodes non-fatal. Resumable via per-stage
persistence in `security_audits.stage_state`. Details: `docs/agent-workflow.md`.

## 7. Database Schema

Implemented (Phase 2) exactly per `docs/database.md`: users, targets,
authorization_records, security_audits, reconnaissance_results, vulnerabilities,
security_reports, audit_logs. Migration head: `afb3ff51caae` (initial schema).
Conventions: UUID PKs; timestamptz with server defaults; enums stored as varchar +
CHECK (`native_enum=False`, values not names); deterministic constraint names via
naming convention; JSONB for semi-structured fields; ON DELETE CASCADE from user →
target → audit → children; `unique(audit_id, fingerprint)` on vulnerabilities;
`AuditLog.meta` ORM attribute ↔ `metadata` column.

## 8. API Structure

Designed in `docs/api.md` (brief endpoints + health, logout, target validate,
global findings, activity).
Also implemented (ADR-011): `POST /api/audits/source` (202), `GET /api/audits`, `/{id}`, `/{id}/findings`,
`/{id}/logs`, `/{id}/report?format=html|pdf&download=`; all owner-scoped (404 for other users).
Implemented: `GET /api/health`; `POST /api/auth/register` (201/409/422),
`POST /api/auth/login` (sets httpOnly cookie, returns token + user; 401 generic),
`POST /api/auth/logout` (204), `GET /api/auth/me`. Routers live in `app/api/`, are
mounted under `/api` in `app/main.py`; protected routes use `CurrentUser`.

## 9. Frontend Structure

Next.js 16 App Router. Route groups: `app/(auth)/` (login, register — public) and
`app/(app)/` (client layout with `Sidebar` + `useCurrentUser`; dashboard, settings).
Protected paths are listed in `proxy.ts` matcher; real auth is the API (401 → login).
All data fetching is client-side through `/api/*`. Built: audits (list + new source audit) and audit
detail (progress polling, findings, logs, report links). Not yet built: targets and a global
findings/reports/activity view (the per-audit page covers findings, report and log). Read
`frontend/node_modules/next/dist/docs/` before writing frontend code (Next 16).

## 10. Security Model

`docs/security-model.md`: authorization gate at API + workflow + tool layers; target
validation (resolve + check all IPs, block private/loopback/link-local/metadata,
allowlist, per-request re-check, manual redirect checks); no shell=True; no bypass
features; honest CVE/CVSS.

## 11. Technology & Dependencies

Per spec: Python/FastAPI/Pydantic/SQLAlchemy, LangGraph/LangChain, Next.js/React/TS/
Tailwind, PostgreSQL, ZAP, Nuclei, Docker Compose.
Added (justified): Alembic (migrations), asyncpg (async driver), Jinja2 (report
templates), httpx (HTTP client), argon2-cffi, PyJWT, email-validator (Phase 3), jinja2, weasyprint (Phase 13; backend
image installs Pango/HarfBuzz/DejaVu fonts). To decide in later phases: PDF renderer
(WeasyPrint vs alternative — Windows local-dev friction), chart library (Recharts),
password hashing lib.

## 12. Environment Configuration

`.env.example` lists all variables (DB, SECRET_KEY, LLM_*, ZAP_*, NUCLEI_PATH, limits,
ALLOW_PRIVATE_TARGETS, TARGET_ALLOWLIST, DEMO_MODE, REPORTS_DIR). Dev machine
(checked 2026-10-02): Windows 11, Python 3.14.6, Node 22.12.0, Docker 27.4.0.
Container images will pin Python 3.12 for library-wheel compatibility.

## 13. Development Progress
| Phase | Status |
|---|---|
| 0 Requirements & architecture | Done |
| 1 Repository structure | Done |
| 2 Database & migrations | Done (2 migrations: initial, source audits) |
| 3 Authentication | Done (+ login throttling, admin bootstrap) |
| 4 Target management | **Blocked** (see §3) |
| 5 Authorization & restrictions | **Blocked** for live targets; source-audit authorization gate done |
| 6-12 Agents, workflow, recon, ZAP, Nuclei, validation, validator | Not started (depend on 4-5) |
| 13 Report generation | Done for source audits (persisted + downloadable); Report *agent* pending the live pipeline |
| 14 Frontend | Auth, dashboard (real data), audits list/detail; targets/global pages pending their APIs |
| 15 Audit progress | Done for source audits (stages, polling, activity log) |
| 16 Demo mode | CLI demo done; fixture demo of the agent pipeline pending |
| 17 Testing | 346 backend (93% cov.) + 24 Vitest + 6 Playwright, all in CI |
| 18 Docker integration | Compose runs and is e2e-tested; ZAP/Nuclei unused |
| 19 End-to-end | Done for the source-audit journey (Playwright, CI job `e2e`) |
| 20 Documentation | Done (13 ADRs, UML, guides, traceability R1-R58, close-out) |
| Extra: grey-box static engine, CLI, CI gating, SARIF, MCP, benchmark, business-logic detectors, chains, fix patches | Done (scope change 2026-10-03b, ADR-008, 010-013) |

## 14. Architecture Decisions

| ADR | Decision | Status |
|---|---|---|
| ADR-001 | LangGraph StateGraph orchestration; LLM never routes | Accepted |
| ADR-002 | PostgreSQL 16 + SQLAlchemy 2 async + Alembic; tests on Postgres | Accepted |
| ADR-003 | Exploitation Agent → SafeValidationAgent (non-destructive) | Accepted |
| ADR-004 | Demo mode swaps tool adapters only; labelled everywhere | Accepted |
| ADR-005 | In-process asyncio jobs + 2 s polling; no Redis/Celery | Accepted |
| ADR-006 | Argon2id + HS256 JWT in httpOnly SameSite=Lax cookie (+ Bearer) | Accepted |
| ADR-007 | Report: Pydantic context → Jinja2 HTML → WeasyPrint PDF | Accepted |
| ADR-008 | Grey-box: source-code analysis + dev intent for business-logic flaws | Accepted |
| ADR-009 | Scanner CLI is dependency-light; independent of the web stack | Accepted |

Other design decisions (2026-10-02): JWT in httpOnly cookie (+ Bearer for tests);
2026-10-03: browser calls same-origin `/api/*`, Next.js rewrites proxy to FastAPI
(`BACKEND_URL`, baked in at build) — keeps the auth cookie first-party; replaces
`NEXT_PUBLIC_API_URL` in `.env.example`. Next.js 16 has breaking changes vs older
versions: read `frontend/node_modules/next/dist/docs/` before writing frontend code;
finding fingerprint unique per audit for idempotency; schema/API additions listed in
changelog.

## 15. Scope Changes

| Date | Original | Change | Reason | Impact | Status |
|---|---|---|---|---|---|
| 2026-10-11 | Full live multi-agent platform | **Delivered as a grey-box static security auditor** (owner chose Option 1; ADR-014). Live pipeline deferred, not in progress. | Target management cannot be produced by the assistant; static auditor is complete and defensible. | UI lists only built pages; ZAP behind a compose profile; traceability rows marked Deferred; criteria 5, 7, 10, 14 explicitly unmet. | Accepted |
| 2026-10-02 | Baseline from PPT | Baseline from owner's brief; PPT sections PENDING | PPT not in repo | SPECIFICATION.md partial | Open until PPT supplied |
| 2026-10-03b | Black-box (DAST) auditor only | **Grey-box**: also ingest the app's source repo + developer description, build an Application Model, and detect business-logic flaws (BOLA/IDOR, function-level & inconsistent authz, workflow bypass, client-trusted values, missing limits, hardcoded secrets, insecure state change). Dynamic scanning retained; source optional but recommended. | Owner's primary goal is finding complex business-logic vulns in developers' own apps; scanners can't infer intended rules. | New agents (Code Intelligence, Business-Logic Reasoning), Application Model artifact, repo-ingestion tool, DB additions (`source_artifacts`, `application_models`, `code_locations`/`detection_source` on vulnerabilities), new deps (tree-sitter, git/zip). Designed in ADR-008 + `docs/business-logic-engine.md`. | Designed; not implemented (prereq: Phases 4–5) |

## 16. Open Issues
- **PPT not provided**: `SPECIFICATION.md` sections marked PENDING stay unfilled; conflicts with the PPT
  are unknown. Provide the PPT and reconcile.
- **Target management blocked** (see §3) — the single dependency for the live audit pipeline.
- **CI**: four jobs (backend, frontend, self-scan, e2e), **green at close-out (commit 5403c07)**; the first
  run (2026-10-09) failed for real reasons, fixed (see §17). Accepted advisory:
  `braces 3.0.3` (GHSA-vfj7-8cjw-p6xm; OSV lists **no patched version**; transitive dev-only dependency of
  eslint-config-next) is recorded in `.secureagent-baseline.json` so CI gates only on NEW high/critical findings.
- ~~No `LICENSE`~~ -- **MIT** chosen by the owner 2026-10-11 (copyright line uses the GitHub handle
  `pranithreddy12`; the owner may replace it with their legal name).
- **Detector accuracy is measured only on an author-written corpus** (94%/94%); no independent real-world
  rate. Login throttling is in-process (per worker); the interrupted-audit sweep assumes one API process.
- CVSS is never populated for OSV findings (reported as "not determined"); advisory CVSS vectors are not
  parsed to a score.
- Local dev DB contains test users (`smoke*@example.com`, `uitest@example.com`).
- `npm audit`: 5 high advisories in dev-only tooling (`braces`); production dependencies report 0;
  OSV flags `braces 3.0.3` (GHSA-vfj7-8cjw-p6xm).

## 17. Resolved Issues
Found by dogfooding (SecureAgent scanning/installing itself) and fixed in the 2026-10-09 close-out:
- **Installed `secureagent scan` crashed on a clean machine** (scanner path imported the ORM package ->
  SQLAlchemy). Fixed by moving enums to `app/core/enums.py`; regression test `test_cli_standalone.py`.
- **`poetry.lock` / `Pipfile.lock` were never scanned** (`.lock` was treated as a binary extension). Fixed;
  regression test goes through real file ingestion.
- Handlers sharing a method name across classes (`get`/`post`) were collapsed by a name->node dict.
- Secret scanner: duplicate report of one key (provider + generic rule); format placeholders
  (`{FAKE}`) and option values (`credentials: "same-origin"`) reported as secrets.
- CLI crashed printing non-ASCII to a Windows cp1252 console.
- Backend dependencies were unpinned (`>=`), so SCA saw none; now pinned in `requirements.lock`.
- Documentation drift: stale traceability rows, a missing changelog entry (UML diagrams), bloated §3.
- Missing required docs (testing, deployment), incomplete README.
- First CI run found: frontend `tsc` failed on a clean checkout (Next generates the global `LayoutProps` type;
  fixed with `npm run typecheck` = `next typegen && tsc --noEmit`); self-scan gate failed on the real `braces`
  advisory (accepted via baseline, no patch exists).
- **Correction**: the 2026-10-09 close-out claimed `frontend/AGENTS.md` / `CLAUDE.md` were untracked, but a
  later `git reset` (used to split commits) silently restored them; they were truly untracked in the follow-up
  commit. Lesson: verify against `git ls-tree HEAD` after the final commit, not before.

## 18. Testing Status
- **Backend: 346 passed, 1 skipped, 0 failed; 93% line coverage (2026-10-11, local run with the DB; CI green).**
  Frontend: 24 Vitest + 6 Playwright. The skipped test is
  PDF rendering, which needs Pango (passes in the backend Docker image). DB-backed tests need
  `make testdb` (PostgreSQL on :55432); they build the schema via the real Alembic migration.
- Static-analysis tests use snippets + the pinned demo; OSV is tested through an injected fake transport
  (a live OSV query was verified manually). Per-area table in `docs/testing.md`.
- **Not tested / absent**: the live audit pipeline and target safety validation (do not exist); frontend
  coverage is not measured (24 unit + 6 browser tests). Lowest coverage: `schemas/target.py` 0% (unused),
  `core/database.py` 69%, `analysis/dependencies.py` 78%, `analysis/osv.py` 84%.
- Verified manually: Docker Compose stack runs; auth through the frontend proxy; UI flows in a browser;
  clean-virtualenv install of the CLI (`scan`, `demo --report`); live OSV scan of this repo's own lockfiles.

## 19. Known Limitations
- The live audit pipeline, ZAP/Nuclei integration, LLM reasoning and audit-progress UI do not exist.
- Single backend replica by design (ADR-005); running audits would be lost on restart (resumable).
- Static analysis cannot prove exploitability, so findings are never `confirmed`; unprotected-endpoint and
  IDOR findings cannot see global middleware / base querysets (low confidence by design).
- Python taint resolves cross-file calls heuristically (import hint / unique name), does not model
  sanitizers, and does not follow class attributes; JS/TS analysis is regex-based (no AST).
- OSV matching uses pinned versions in lockfiles (no range resolution); needs network (skipped gracefully).
- Frontend has 24 Vitest tests and 6 Playwright e2e tests (own CI job; need Docker). `vitest@5` required `@types/node@^22`; vitest 3 pulled
  critical advisories (tinypool/mocker), which the project's own OSV scan would have flagged.
- Login throttling is in-process (per worker); the interrupted-audit sweep assumes one API process.
- Intraprocedural IDOR heuristic only (it also flags legitimate by-id lookups of shared catalogue data).
- Fix patches are verified by re-scan and parse only (behaviour preservation is not proven); they cover seven
  finding types and single files.
- Workflow-order detection is a handler-local heuristic (Python): a state machine in the model/DB or a helper
  like `order.ship()` is invisible, so findings stay `suspicious` (confidence 0.4-0.5).
- The MCP server (docs/mcp.md) implements tools over stdio only, by hand; no resources/prompts/HTTP.
- Accuracy is measured only on a small author-written corpus (`docs/benchmark.md`, 94%/94%); no
  independent real-world detection rate exists.
- Business-logic detectors (ADR-010) are Python-only; they cover client-trusted values, mass assignment and
  declared intent rules, not workflow-order. A serializer or middleware outside the handler can neutralise a
  flagged pattern, so findings stay `suspicious`.
- Some real vulnerabilities will remain `likely`/`suspicious` because only non-destructive validation is intended.

## 20. Future Improvements

- Scheduled audits, CI/CD webhooks, continuous monitoring (Celery/Redis or similar
  when needed — would supersede ADR-005).
- SSE progress streaming.
- Authenticated scanning with user-supplied test credentials (not in baseline).
- Deep taint/dataflow SAST (CodeQL-class) — ADR-008 takes a lighter structural
  Application Model; full dataflow analysis is future work.
- More language grammars for Code Intelligence beyond the initial stack(s).

## 21. Lessons Learned

- Long file writes in this environment have occasionally been cut off mid-file;
  verify every large generated file is complete (end-of-file check) before moving on.
- pydantic-settings JSON-decodes `list[...]` env vars; CSV lists need
  `Annotated[list[str], NoDecode]` plus a `mode="before"` validator.
- Alembic autogenerate duplicates CHECK constraints for `Enum(create_constraint=True,
  native_enum=False)` under a naming convention. Delete the explicit enum
  `sa.CheckConstraint(... IN (...))` lines from generated migrations; the Enum column
  type creates the single `ck_<table>_<enum>` constraint. Verify with `alembic check`.
- Frontend proxy returns 500 while the backend container restarts (migrations at
  boot); fixed for cold start with a backend healthcheck + `service_healthy`.
  Always re-run smoke checks after the backend reports healthy.
- WeasyPrint on Windows raises `OSError` at import (no Pango) — `pytest.importorskip`
  does not catch that; catch `(ImportError, OSError)` and skip. On Python 3.14,
  `pip install weasyprint` hung building from source; `--only-binary=:all:` worked.
- Docker builds can fail on transient Debian mirror timeouts; apt uses
  `-o Acquire::Retries=5`.
- Bash heredocs containing many nested quotes have failed to parse in this
  environment; use the Write tool for multi-file source creation.
- CLI printed to a legacy Windows console (cp1252) raised UnicodeEncodeError on
  non-ASCII (e.g. the "->" arrow U+2192). Fixed: `_force_utf8_output()` reconfigures
  stdout/stderr to utf-8 with errors=replace at CLI start.

- **Dogfood the product and test the *installed* artifact.** Scanning this repo and installing into a
  clean virtualenv found bugs that 200 unit tests missed (clean-install crash, `.lock` never scanned).
  Unit tests that call a parser directly bypass ingestion; add an end-to-end test per integration seam.
- Scripted doc edits that fail halfway leave docs partly updated; make edit scripts all-or-nothing
  (write only at the end) and re-verify with grep afterwards.
- Prefer a script file over a long shell heredoc for multi-line edits in this environment.

## 22. Current Session Summary
2026-10-11 final close-out. Work since the 2026-10-09 audit (details in `PROJECT_CHANGELOG.md`):
- Detection: business-logic detectors + intent spec (ADR-010), authorization matrix, workflow-order heuristic,
  attack chains (ADR-012); MCP server; accuracy benchmark; verified fix patches (ADR-013).
- Product: persisted source audits end to end (ADR-011) -- API, runner, migration, audit pages, report
  download; login throttling; interrupted-audit sweep; admin bootstrap.
- Quality: 346 backend / 24 Vitest / 6 Playwright tests; four-job CI, green. The project's own scanner found
  and fixed 3 false positives in its code; the benchmark found 2 detector gaps.
- Acceptance criteria: 14 done, 2 done for source audits only, 8 partial, 4 not built (live pipeline).
- Honest state: a complete, tested grey-box static security auditor; the live multi-agent pipeline is **not
  built** and is blocked on the two owner-supplied target-management files.
**Decision (2026-10-11):** owner chose Option 1 -- closed as a grey-box static security auditor (ADR-014).
**Next (owner):** provide the PPT for the pending SPECIFICATION sections (LICENSE: MIT, done). Resuming the live
pipeline (Option 2) needs the two target-management files. See `docs/PROJECT_CLOSEOUT.md` §5-6.
