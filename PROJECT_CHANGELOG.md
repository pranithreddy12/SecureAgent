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
