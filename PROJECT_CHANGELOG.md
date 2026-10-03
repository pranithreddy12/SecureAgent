# SecureAgent Project Changelog

Append-only. Never rewrite past entries.

## 2026-10-02

### Added
- `SPECIFICATION.md` — original baseline, extracted from the owner's brief (PPT not
  provided; PPT-only sections marked PENDING).
- `PROJECT_MEMORY.md`, `PROJECT_CHANGELOG.md`.
- `docs/REQUIREMENTS_TRACEABILITY.md`.
- Design docs: `docs/architecture.md`, `docs/agent-workflow.md`, `docs/database.md`,
  `docs/api.md`, `docs/security-model.md`.
- ADR-001 (LangGraph), ADR-002 (PostgreSQL/SQLAlchemy/Alembic), ADR-003 (Safe
  Validation Agent), ADR-004 (Demo Mode), ADR-005 (asyncio background jobs + polling).
- `.gitignore`, `.env.example`, README stub; git repository initialised.

### Architecture
- Exploitation Agent implemented as controlled SafeValidationAgent (ADR-003).
- No Redis/Celery initially (ADR-005).
- Schema additions beyond the brief: `fingerprint`, `status_reason`, `sources` on
  vulnerabilities; `is_demo`, `stage_state` on audits; `statement` on authorization
  records; `validation_message` on targets.
- API additions: `/api/health`, `/api/auth/logout`, `/api/targets/{id}/validate`,
  `/api/findings`, `/api/activity`.

### Notes
- Phase 0 complete. No application code yet.

## 2026-10-03

### Added
- Backend skeleton: FastAPI app factory, pydantic-settings `Settings` (all env vars,
  validated limits, CSV allowlist), `GET /api/health`, pytest + ruff config,
  `requirements.txt` / `requirements-dev.txt`.
- Frontend: Next.js 16 + React 19 + TypeScript + Tailwind v4 (create-next-app),
  boilerplate replaced with a dark SecureAgent placeholder, standalone output.
- `docker/backend.Dockerfile`, `docker/frontend.Dockerfile`, `docker-compose.yml`
  (postgres, zap, backend, frontend, juice-shop under `lab` profile), `.dockerignore`,
  `Makefile`, `.gitattributes` (LF line endings).

### Changed
- `.env.example`: `NEXT_PUBLIC_API_URL` replaced by `BACKEND_URL` (frontend proxies
  `/api/*` to the backend so the auth cookie is first-party).

### Fixed
- `TARGET_ALLOWLIST` CSV parsing (pydantic-settings tried to JSON-decode the list).

### Tests
- Backend 2/2 passing; ruff clean. Frontend lint, typecheck, build passing.
- Docker images not built: Docker Desktop daemon not running. Compose config valid.

### Notes
- Phase 1 complete.
