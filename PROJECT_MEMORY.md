# SecureAgent Project Memory

> Read this first in every session, then verify against the actual repository.
> Current state lives here; history lives in `PROJECT_CHANGELOG.md`; the original
> baseline lives in `SPECIFICATION.md`. Never store secrets in this file.

Last updated: 2026-10-03 (end of Phase 3)

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

### In Progress
- Nothing.

### Planned
- Phases 4–20 per brief (§36). Next: Phase 4 target management.
- Backend packages (`models`, `schemas`, `services`, `agents`, `tools`, `workflows`,
  `security`, `reports`, `demo`) are created in the phase that first puts code in them,
  not as empty placeholders.

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
Details: `docs/agent-workflow.md` §4.

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

Designed in `docs/architecture.md` §5. Not yet implemented.

## 10. Security Model

`docs/security-model.md`: authorization gate at API + workflow + tool layers; target
validation (resolve + check all IPs, block private/loopback/link-local/metadata,
allowlist, per-request re-check, manual redirect checks); no shell=True; no bypass
features; honest CVE/CVSS.

## 11. Technology & Dependencies

Per spec: Python/FastAPI/Pydantic/SQLAlchemy, LangGraph/LangChain, Next.js/React/TS/
Tailwind, PostgreSQL, ZAP, Nuclei, Docker Compose.
Added (justified): Alembic (migrations), asyncpg (async driver), Jinja2 (report
templates), httpx (HTTP client), argon2-cffi, PyJWT, email-validator (Phase 3). To decide in later phases: PDF renderer
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
| 4 Target management | ⏭ Next |
| 5–20 | Not started |

## 14. Architecture Decisions

| ADR | Decision | Status |
|---|---|---|
| ADR-001 | LangGraph StateGraph orchestration; LLM never routes | Accepted |
| ADR-002 | PostgreSQL 16 + SQLAlchemy 2 async + Alembic; tests on Postgres | Accepted |
| ADR-003 | Exploitation Agent → SafeValidationAgent (non-destructive) | Accepted |
| ADR-004 | Demo mode swaps tool adapters only; labelled everywhere | Accepted |
| ADR-005 | In-process asyncio jobs + 2 s polling; no Redis/Celery | Accepted |
| ADR-006 | Argon2id + HS256 JWT in httpOnly SameSite=Lax cookie (+ Bearer) | Accepted |

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

## 16. Open Issues

- PPT not yet provided (affects SPECIFICATION.md PENDING sections).
- PDF renderer choice pending (Phase 13).
- No admin bootstrap: every registration is `auditor`. Need a CLI/seed command to
  promote a user to `admin` before any admin-only feature ships.
- No login rate limiting / lockout yet (not in brief; consider before deployment).
- Local dev DB contains smoke-test users (`smoke*@example.com`) from Phase 3 checks.
- `npm audit`: 5 high advisories in **dev-only** build tooling (`braces`, via
  eslint/tailwind toolchain); production deps report 0. Re-check on upgrades.

## 17. Resolved Issues

- None yet.

## 18. Testing Status

- Backend: 30 tests passing. Auth: hashing, register (normalised email, no hash
  leak, duplicate case-insensitive 409, validation 422, role injection ignored), login
  cookie flags, me via cookie and Bearer, indistinguishable login failures, bad
  tokens (garbage, expired, unknown user, wrong key, alg=none), logout, deleted user.
- Earlier: health, settings, and DB tests run against real
  Postgres through the real Alembic migration (downgrade base → upgrade head):
  full graph round-trip, enum value storage, unique fingerprint, unique email,
  CHECK constraints (progress, status, confidence, severity), cascade delete,
  FK enforcement. ruff clean. DB tests need `make testdb` (localhost:55432) or
  `TEST_DATABASE_URL`.
- Frontend: eslint, `tsc --noEmit`, `next build` passing.
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
- Bash heredocs containing many nested quotes have failed to parse in this
  environment; use the Write tool for multi-file source creation.

## 22. Current Session Summary

2026-10-03: Phases 1–3 completed and committed. Full stack (postgres, zap, backend,
frontend) runs under compose; auth verified end-to-end through the frontend proxy.
**Next task: Phase 4 — target management**: Pydantic schemas, `target_service`,
`/api/targets` CRUD with ownership checks (404 for others' targets),
`MAX_TARGETS_PER_USER`, URL normalisation, scope default = target host, URL/scope
change resets authorization, delete blocked while an audit runs; tests.
Phase 5 then adds safety validation + `/authorize` + `/validate`.
