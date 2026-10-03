# SecureAgent Project Memory

> Read this first in every session, then verify against the actual repository.
> Current state lives here; history lives in `PROJECT_CHANGELOG.md`; the original
> baseline lives in `SPECIFICATION.md`. Never store secrets in this file.

Last updated: 2026-10-04 (static engine + dangerous-sink pack; Phases 4–5 blocked)

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
- Phase 0: specification, memory, changelog, traceability, design docs, ADR-001…005,
  `.gitignore`, `.env.example`, README stub, git init.
- Phase 1: backend skeleton (`backend/app/main.py` app factory, `core/config.py`
  Settings covering every `.env.example` variable, `GET /api/health`), pytest + ruff;
  Next.js 16 frontend (App Router, TS, Tailwind v4, standalone output, `/api/*`
  rewrite to backend); `docker/backend.Dockerfile`, `docker/frontend.Dockerfile`,
  `docker-compose.yml` (postgres, zap, backend, frontend, `lab` profile juice-shop),
  Makefile, `.gitattributes` (LF), `.dockerignore`.
- Phase 2: SQLAlchemy 2 models for all 8 tables (`backend/app/models/`: user, target
  [+AuthorizationRecord], audit [+ReconnaissanceResult, AuditLog], finding
  [Vulnerability], report, enums, base); async engine/session + `get_db` dependency
  (`app/core/database.py`); Alembic (async template, URL from settings) with initial
  migration `afb3ff51caae`; backend container runs `alembic upgrade head` on start.
- Phase 3: authentication (ADR-006) — `app/core/security.py` (Argon2id, JWT),
  `app/schemas/auth.py`, `app/services/user_service.py`, `app/api/deps.py`
  (`DbSession`, `CurrentUser`, `require_admin`), `app/api/auth.py`
  (register/login/logout/me). Compose: backend healthcheck; frontend waits for it.
- Phase 14 (part 1): frontend foundation — dark design tokens (`app/globals.css`,
  incl. severity colours), `lib/api.ts` (same-origin fetch wrapper, `ApiError`,
  `safeNextPath` open-redirect guard), `types/api.ts`, `services/auth.ts`,
  `proxy.ts` (Next 16 replacement for middleware: cookie-presence redirect to
  `/login?next=`), `hooks/useCurrentUser.ts` (401 → login), `components/ui.tsx`,
  `AuthShell`, `Sidebar` (unbuilt sections shown disabled "soon", never fake pages),
  `SystemStatus`; pages `/login`, `/register` (auto-login), `/dashboard` (live
  health + honest empty state, no simulated metrics), `/settings` (account + status),
  `/` → `/dashboard`.
- Phase 13 (rendering layer, ADR-007): `app/schemas/report.py` (`ReportContext`,
  `ReportFinding`, `CvssScore`, `TimelineEntry`; derived views: reportable findings
  sorted by severity, false-positive split, severity/status counts, OWASP/CWE
  grouping, deterministic executive summary; `NO_CVE`/`NO_CVSS` fallback strings),
  `app/reports/templates/report.html` (all 19 sections, A4 print CSS, page numbers,
  DEMO watermark/banner), `app/reports/renderer.py` (`render_html` autoescaped +
  StrictUndefined; `render_pdf` via WeasyPrint, lazy import). Not yet wired to the
  DB or an API — the Report Agent (which builds `ReportContext` from an audit) and
  `/api/audits/{id}/report*` endpoints come once audits exist.

### In Progress
- Phase 14 frontend: auth pages + app shell done; data pages wait on their APIs.

### Blocked
- **Phases 4–5 (target management, safety validation, authorization)** — 2026-10-03:
  two attempts to generate this code (`backend/app/security/target_validation.py`,
  then `backend/app/services/target_service.py`) were stopped by an automated safety
  classifier during generation. The assistant may not regenerate that content.
  Requirements are unchanged (not a scope change). Path forward: the owner writes
  the target service/endpoints and the safety validator per `docs/api.md` and
  `docs/security-model.md` §2; the assistant can then review, test and integrate.
  `backend/app/schemas/target.py` (target/authorization Pydantic schemas) was fully
  written before the second stop; it is left **untracked and uncommitted** pending
  the owner's decision.
- Phases 6–13 (agents, workflow, recon, ZAP, Nuclei, validation, validator,
  reports) depend on targets/authorization; not started.

### Planned
- Phases 4–20 per brief (§36). Next: Phase 4 target management.
- Backend packages (`models`, `schemas`, `services`, `agents`, `tools`, `workflows`,
  `security`, `reports`, `demo`) are created in the phase that first puts code in them,
  not as empty placeholders.
- **Grey-box business-logic engine (ADR-008, `docs/business-logic-engine.md`)** —
  designed 2026-10-03; phases BL-1…BL-7. Most phases depend on Phases 4–5.
  **BL-1 + BL-3 built & tested (static, standalone, no DB/web needed):**
  `app/analysis/ingest.py` (read-only repo walk; skips vendored/VCS/binary; size &
  file-count limits; never executes repo code), `app/analysis/secrets.py` (provider
  signatures + generic secret-keyword/entropy detection; redaction + fingerprint,
  full value never stored), `app/analysis/scanner.py`, `app/cli.py`
  (`python -m app.cli scan <dir>`, text/JSON, exit 1 on findings → CI-gating).
  `make scan DIR=...`. Verified on the project's own tree.
  **BL-2 built & tested:** `app/analysis/routes.py` extracts HTTP routes (Python via
  stdlib `ast` for FastAPI/Flask-style; JS/TS via regex for Express-style) and flags
  state-changing or privileged endpoints with no detected auth
  dependency/decorator/middleware → `missing_function_level_authorization` findings
  (deliberately 0.4 confidence / status `suspicious`, since global middleware is
  invisible to static analysis; never `confirmed`). **Report wiring built:**
  `app/analysis/reporting.py` maps a `ScanResult` → the Phase-13 `ReportContext`;
  CLI `--report out.html` / `--pdf out.pdf` produce the 19-section professional
  report from a pure source scan. Real run on our own `app/`: 5 routes found, 3
  unauthenticated POSTs flagged for review (correct — login/register are public).
  **Dependency/SCA built & tested:** `app/analysis/dependencies.py` parses
  requirements.txt / Pipfile.lock / poetry.lock / package-lock.json (PyPI + npm);
  `app/analysis/osv.py` queries the public OSV database (osv.dev, no key, stdlib
  urllib; injectable fetch for offline tests) for known advisories on declared
  versions. Findings → A06/CWE-1104, status `likely`, CVE only when the advisory id
  is a real CVE (never invented). CLI `--no-osv` for offline; graceful on network
  failure. Real run: flagged PyYAML 5.1 (critical) and requests 2.19.0 (high).
  **Batch #1 dangerous-sink pack built & tested:** `app/analysis/sinks.py` (Python via
  `ast` with import-alias resolution; JS/TS via regex) detects insecure
  deserialization (pickle/yaml.load/marshal → CWE-502/A08), command execution
  (os.system, subprocess shell=True → CWE-78/A03), code execution (eval/exec → CWE-95),
  weak hashing (md5/sha1 → CWE-327/A02), disabled TLS verification (verify=False →
  CWE-295), insecure temp files (mktemp → CWE-377), XXE-prone XML parsing (CWE-611),
  and JS innerHTML XSS sinks (CWE-79). Honest status: definite misconfig (weak crypto,
  TLS) → likely; input-dependent sinks → suspicious; never confirmed. Wired into
  scanner/CLI/report. Real run flagged all 6 planted sinks correctly; safe variants
  (yaml.safe_load, sha256, argv subprocess, verify=True) not flagged.

### Deferred
- Continuous / scheduled audits, CI/CD integration (architecture extensible only).

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
Implemented: `GET /api/health`; `POST /api/auth/register` (201/409/422),
`POST /api/auth/login` (sets httpOnly cookie, returns token + user; 401 generic),
`POST /api/auth/logout` (204), `GET /api/auth/me`. Routers live in `app/api/`, are
mounted under `/api` in `app/main.py`; protected routes use `CurrentUser`.

## 9. Frontend Structure

Next.js 16 App Router. Route groups: `app/(auth)/` (login, register — public) and
`app/(app)/` (client layout with `Sidebar` + `useCurrentUser`; dashboard, settings).
Protected paths are listed in `proxy.ts` matcher; real auth is the API (401 → login).
All data fetching is client-side through `/api/*`. Not yet built: targets, audits,
findings, reports, activity pages (APIs don't exist yet). Read
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
| 0 Requirements & architecture | ✅ Done 2026-10-02 |
| 1 Repository structure | ✅ Done 2026-10-03 |
| 2 Database & migrations | ✅ Done 2026-10-03 |
| 3 Authentication | ✅ Done 2026-10-03 |
| 4 Target management | ⛔ Blocked (see §3) |
| 5 Authorization & restrictions | ⛔ Blocked (see §3) |
| 6–13 | Not started (depend on 4–5) |
| 13 Report generation | 🟡 Rendering layer done (HTML+PDF); agent/API pending audits |
| Static engine (secrets + deps/OSV + sinks + routes/authz + report) | ✅ Done 2026-10-04 (standalone CLI + HTML/PDF) |
| 14 Frontend | 🟡 Part 1 done (auth pages, shell) |
| 15–20 | Not started |

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
| 2026-10-02 | Baseline from PPT | Baseline from owner's brief; PPT sections PENDING | PPT not in repo | SPECIFICATION.md partial | Open until PPT supplied |
| 2026-10-03b | Black-box (DAST) auditor only | **Grey-box**: also ingest the app's source repo + developer description, build an Application Model, and detect business-logic flaws (BOLA/IDOR, function-level & inconsistent authz, workflow bypass, client-trusted values, missing limits, hardcoded secrets, insecure state change). Dynamic scanning retained; source optional but recommended. | Owner's primary goal is finding complex business-logic vulns in developers' own apps; scanners can't infer intended rules. | New agents (Code Intelligence, Business-Logic Reasoning), Application Model artifact, repo-ingestion tool, DB additions (`source_artifacts`, `application_models`, `code_locations`/`detection_source` on vulnerabilities), new deps (tree-sitter, git/zip). Designed in ADR-008 + `docs/business-logic-engine.md`. | Designed; not implemented (prereq: Phases 4–5) |

## 16. Open Issues

- PPT not yet provided (affects SPECIFICATION.md PENDING sections).
- No admin bootstrap: every registration is `auditor`. Need a CLI/seed command to
  promote a user to `admin` before any admin-only feature ships.
- No login rate limiting / lockout yet (not in brief; consider before deployment).
- Local dev DB contains test users (`smoke*@example.com`, `uitest@example.com`) from
  manual checks.
- Secret scanner is regex+entropy (gitleaks-class), not dataflow; may miss obfuscated
  secrets and flag test fixtures. Tune rules as real repos are scanned.
- Route/authz detection is per-handler; it cannot see **global** middleware/router-level
  guards, so unprotected-endpoint findings are low-confidence "review" items by design.
  FastAPI `Annotated[User, Depends(...)]` annotations aren't yet parsed as guards
  (only signature defaults + decorators + `dependencies=`); acceptable (such routes
  are usually GET and unflagged). Add annotation parsing when tuning.
- SCA matches declared lockfile versions to OSV advisories; it does not yet resolve
  transitive ranges beyond what the lockfile pins, nor yarn.lock. OSV detail fetch is
  capped (MAX_DETAIL_FETCHES=150) and needs network (skipped/graceful otherwise).
- `npm audit`: 5 high advisories in **dev-only** build tooling (`braces`, via
  eslint/tailwind toolchain); production deps report 0. Re-check on upgrades.

## 17. Resolved Issues

- None yet.

## 18. Testing Status

- Backend: static-analysis + report tests (no DB): 51 passed + 1 skipped (PDF).
  Sink tests (test_sinks.py, 14): each category detected, safe variants not flagged,
  alias-resolved XXE, status/severity mapping, report HTML, benign code clean.
  Dependency/OSV tests (test_dependencies.py, 9): lockfile parsers offline, OSV
  mapping via injected fake transport, scanner integration, --no-osv, graceful
  network-failure, CVE-vs-GHSA id handling. No test hits the network.
  Route tests (test_route_scan.py): FastAPI/Flask/Express guard detection, only
  unprotected sensitive endpoints flagged, benign GETs ignored, syntax-error files
  skipped, scan→report HTML renders with honest status and redacted secrets. Secret scanner:
  10 tests (detection of planted fakes, skips vendored/VCS/binary, placeholders & env
  refs ignored, full value never leaks, CLI text/JSON/exit codes, clean repo exit 0,
  bad path exit 2). DB-backed tests (models, auth) require the test Postgres container
  (`make testdb`); they errored this run only because Docker Desktop was stopped — not
  a code regression. Full suite last green: 37 passed + 1 skipped (before Docker went down). Auth: hashing, register (normalised email, no hash
  leak, duplicate case-insensitive 409, validation 422, role injection ignored), login
  cookie flags, me via cookie and Bearer, indistinguishable login failures, bad
  tokens (garbage, expired, unknown user, wrong key, alg=none), logout, deleted user.
- Earlier: health, settings, and DB tests run against real
  Postgres through the real Alembic migration (downgrade base → upgrade head):
  full graph round-trip, enum value storage, unique fingerprint, unique email,
  CHECK constraints (progress, status, confidence, severity), cascade delete,
  FK enforcement. ruff clean. DB tests need `make testdb` (localhost:55432) or
  `TEST_DATABASE_URL`.
- Reports: 8 tests (all 19 sections, false positives excluded from counts but
  listed, CVE/CVSS never invented, untrusted content escaped, DEMO label only on demo,
  deterministic summary, empty-audit wording, PDF). Locally 7 pass + PDF skipped (no
  Pango on Windows); in the backend container all 8 pass. Sample PDF (5 A4 pages)
  checked: sections, page numbers, DEMO watermark, fallback strings.
  Container test run: `MSYS_NO_PATHCONV=1 docker compose run --rm --no-deps -e HOME=/tmp
  -v "$(pwd -W)/backend/tests:/app/tests:ro" backend sh -c "pip install --user pytest
  anyio httpx && python -m pytest tests/test_reports.py"` (Git Bash rewrites `/tmp`
  paths unless MSYS_NO_PATHCONV=1).
- Frontend: eslint, `tsc --noEmit`, `next build` passing. Manually verified in the
  running stack (browser pane): unauthenticated redirects with `?next=`, register →
  auto-login → dashboard with live health, settings shows account, wrong password
  shows the API error, sign-out → /login and `/api/auth/me` 401, auth cookie not
  readable from JS. No automated frontend tests yet (Phase 17).
- Docker: backend + frontend images build; postgres+backend+frontend start, migrations
  apply on boot, `/api/health` reachable directly (8000) and via the frontend proxy
  (3000). ZAP container not yet started/pulled (Phase 9).
- Known noise: StarletteDeprecationWarning about httpx in TestClient (upstream).

## 19. Known Limitations

- (Design) Single backend replica; running audits interrupted by restart (resumable).
- (Design) Some real vulnerabilities will remain `likely`/`suspicious` because only
  non-destructive validation is performed.

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

## 22. Current Session Summary

2026-10-04: Built batch #1 of broader vulnerability coverage — the dangerous-sink
detector pack (`app/analysis/sinks.py`): insecure deserialization, command/code
execution, weak hashing, disabled TLS verification, insecure temp files, XXE, JS XSS
sinks. AST-based for Python with import-alias resolution; regex for JS. Wired into
scanner/CLI/report with honest status (definite misconfig = likely, input-dependent
sink = suspicious, never confirmed). 51 static/report tests pass (+1 PDF skip). The
standalone scanner now covers OWASP A01(partial)/A02/A03(sinks)/A05/A06/A08.
**Next (per the OWASP coverage map in this session):** batch #2 taint-lite (connect
request input → sinks for real SQL/command injection/SSRF), batch #3 IDOR/ownership,
batch #4 security misconfiguration. Live web pipeline still needs Phases 4–5 (blocked);
`backend/app/schemas/target.py` untracked.
