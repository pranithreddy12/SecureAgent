# ADR-009: The `secureagent` scanner is dependency-light and independent of the web stack

- **Date:** 2026-10-09
- **Status:** Accepted

## Context
The static-analysis engine (ADR-008) is the most immediately useful part of SecureAgent: developers
and CI systems should be able to `pip install` it and run `secureagent scan .` with no database, no
web server and no LLM. A clean-virtualenv test on 2026-10-09 showed the installed command crashed
because the scanner path imported `app.models` (SQLAlchemy) through a shared enum module. The
development virtualenv hid this because it has the full web stack installed.

## Decision
- The scanner/CLI import path (`app.analysis`, `app.cli`, `app.schemas.report`, `app.reports`) may
  depend only on the standard library, **Jinja2** and **Pydantic**. WeasyPrint is an optional `pdf`
  extra (lazy import). The package declares exactly these dependencies.
- Shared enums live in `app/core/enums.py` (stdlib only); `app/models/enums.py` re-exports them so the
  ORM keeps its import path.
- A regression test (`tests/test_cli_standalone.py`) runs the CLI in a subprocess with SQLAlchemy,
  FastAPI, asyncpg, Alembic, Argon2, PyJWT and Uvicorn imports poisoned, covering `scan` (text/JSON/SARIF),
  `demo` and `--report`.
- The CI workflow installs the package into a clean environment and runs `secureagent demo` and
  `secureagent scan .`.

## Alternatives
- Declare the full web stack as dependencies of the CLI — heavy install for a linter-like tool.
- Split into two distributions (`secureagent` and `secureagent-web`) — cleaner long term, but more
  packaging overhead than the project needs now; revisit if the pipeline ships.

## Consequences
- New code on the scanner path must not import `app.models`, `app.core.config`, `app.core.database`
  or anything FastAPI/SQLAlchemy-related; the standalone test will fail if it does.
- The ORM package still imports SQLAlchemy eagerly, as is normal for the web application.
