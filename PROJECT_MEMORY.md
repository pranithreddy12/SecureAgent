# SecureAgent Project Memory

> Read this first in every session, then verify against the actual repository.
> Current state lives here; history lives in `PROJECT_CHANGELOG.md`; the original
> baseline lives in `SPECIFICATION.md`. Never store secrets in this file.

Last updated: 2026-10-03 (end of Phase 1)

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

### In Progress
- Nothing.

### Planned
- Phases 2–20 per brief (§36). Next: Phase 2 database models + Alembic migrations.
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

Designed: users, targets, authorization_records, security_audits,
reconnaissance_results, vulnerabilities, security_reports, audit_logs.
Additions beyond the brief are marked (+) in `docs/database.md`.
Not yet implemented; no migrations exist.

## 8. API Structure

Designed in `docs/api.md` (brief endpoints + health, logout, target validate,
global findings, activity). Not yet implemented.

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
templates), httpx (HTTP client). To decide in later phases: PDF renderer
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
| 2 Database & migrations | ⏭ Next |
| 3–20 | Not started |

## 14. Architecture Decisions

| ADR | Decision | Status |
|---|---|---|
| ADR-001 | LangGraph StateGraph orchestration; LLM never routes | Accepted |
| ADR-002 | PostgreSQL 16 + SQLAlchemy 2 async + Alembic; tests on Postgres | Accepted |
| ADR-003 | Exploitation Agent → SafeValidationAgent (non-destructive) | Accepted |
| ADR-004 | Demo mode swaps tool adapters only; labelled everywhere | Accepted |
| ADR-005 | In-process asyncio jobs + 2 s polling; no Redis/Celery | Accepted |

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
- Docker Desktop daemon was not running on 2026-10-03: images not yet built;
  `docker compose config` validated only. Start Docker Desktop and run `make up`.
- `npm audit`: 5 high advisories in **dev-only** build tooling (`braces`, via
  eslint/tailwind toolchain); production deps report 0. Re-check on upgrades.

## 17. Resolved Issues

- None yet.

## 18. Testing Status

- Backend: 2 tests passing (health endpoint, allowlist CSV parsing); ruff clean.
- Frontend: eslint, `tsc --noEmit`, `next build` passing.
- Docker images: not built (daemon down).
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

## 22. Current Session Summary

2026-10-03: Phase 1 completed — backend/frontend skeletons, Dockerfiles, compose,
Makefile. Local dev: `backend/.venv` (Python 3.14) with `requirements-dev.txt`.
**Next task: Phase 2 — SQLAlchemy models for all 8 tables per `docs/database.md`,
async session, Alembic initial migration, tests against Postgres** (needs Docker
Desktop running for the test database).
