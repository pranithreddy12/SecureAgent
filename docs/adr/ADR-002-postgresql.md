# ADR-002: PostgreSQL + SQLAlchemy 2 + Alembic

- **Date:** 2026-10-02
- **Status:** Accepted

## Context
The PPT specifies PostgreSQL. Findings, recon results and logs are semi-structured.

## Decision
PostgreSQL 16 via SQLAlchemy 2.x ORM (async engine with `asyncpg`), Alembic for
migrations, `jsonb` for semi-structured fields (recon data, validation results,
CVSS, scope), UUID primary keys, DB-level constraints for idempotency
(`unique(audit_id, fingerprint)`).

Tests use a PostgreSQL instance (Docker) to avoid SQLite/Postgres type drift.

## Alternatives
- SQLite — no `jsonb`, different behaviour; rejected for runtime.
- MongoDB — not in the specification.

## Consequences
- Alembic is an added dependency (standard companion of SQLAlchemy).
- Running tests requires a Postgres container.
