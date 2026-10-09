# SecureAgent – Deployment

What can be deployed **today**: the web application skeleton (Next.js frontend with
register/login/dashboard/settings, FastAPI backend with authentication and health endpoints,
PostgreSQL with migrations) and the `secureagent` command-line scanner. The audit pipeline
(targets → recon → ZAP/Nuclei → agents) is **not implemented yet**, so the `zap` and `juice-shop`
services are defined but not used by the backend.

## Quick start (Docker Compose)

```bash
cp .env.example .env
# edit .env: set SECRET_KEY (>= 32 chars), POSTGRES_PASSWORD, ZAP_API_KEY to random values
python -c "import secrets; print(secrets.token_urlsafe(48))"      # e.g. for SECRET_KEY

docker compose up --build -d          # or: make up
docker compose ps                     # backend should become "healthy"
```

| Service | Purpose | Reachable at |
|---|---|---|
| `frontend` | Next.js app; proxies `/api/*` to the backend so the auth cookie is first-party | http://localhost:3000 |
| `backend` | FastAPI; runs `alembic upgrade head` on start, then serves | http://localhost:8000 (`/docs`, `/api/health`) |
| `postgres` | PostgreSQL 16, named volume `pgdata` | internal only |
| `zap` | OWASP ZAP daemon (API key required) — *not yet used by the backend* | internal only |
| `juice-shop` | Intentionally vulnerable lab target, profile `lab` — *not yet used* | `docker compose --profile lab up` |

The first backend build is slow on a poor connection (it downloads system packages for PDF
rendering); later builds reuse the cached layer.

## Configuration

Everything is configured through environment variables; `.env.example` lists all of them and a
test checks it stays in sync with the settings class. Important ones:

| Variable | Notes |
|---|---|
| `SECRET_KEY` | JWT signing key. **Required, ≥ 32 characters**; the app refuses to start otherwise. |
| `DATABASE_URL` / `POSTGRES_*` | Compose builds the URL from the `POSTGRES_*` values. |
| `COOKIE_SECURE` | Set `true` whenever the site is served over HTTPS. |
| `FRONTEND_ORIGIN` | CORS allow-list entry for the browser origin. |
| `ALLOW_PRIVATE_TARGETS`, `TARGET_ALLOWLIST` | Reserved for target safety validation (not implemented yet). |
| `DEMO_MODE` | Reserved for the audit pipeline demo; the static demo is `secureagent demo`. |
| `LLM_API_KEY`, `LLM_MODEL` | Optional; unused until the agent pipeline exists. |

Never commit `.env`. It is git-ignored; `.env.example` contains placeholders only.

## Reproducible builds

`backend/requirements.txt` states the intended dependencies; the Docker image installs the exact
pinned set in `backend/requirements.lock` (45 packages, generated on `python:3.12-slim`, the
image's base). Regenerate it after changing `requirements.txt`:

```bash
docker run --rm -v "$PWD/backend/requirements.txt:/in/requirements.txt:ro" python:3.12-slim \
  sh -c "pip install -q -r /in/requirements.txt && pip freeze --exclude-editable" > /tmp/lock
# then prepend the two header comment lines already in backend/requirements.lock
```

SecureAgent scans its own lockfile against OSV: `secureagent scan backend --exclude tests/`.

## Running without Docker (development)

```bash
# backend
cd backend && python -m venv .venv && .venv/Scripts/python -m pip install -r requirements-dev.txt
make testdb                                   # throwaway PostgreSQL for tests
.venv/Scripts/python -m uvicorn app.main:app --reload     # needs DATABASE_URL, SECRET_KEY in .env

# frontend
cd frontend && npm ci && npm run dev          # http://localhost:3000 (set BACKEND_URL if not :8000)
```

## The scanner as a tool

```bash
pip install -e backend            # installs the `secureagent` command (no database required)
secureagent scan .                # see docs/static-analysis.md and docs/ci/github-actions-example.yml
```

## Production notes and known limits

- Single backend replica by design (ADR-005): audits will run as in-process background tasks.
- Terminate TLS in front of the stack (reverse proxy) and set `COOKIE_SECURE=true`.
- There is **no login rate limiting or account lockout** yet; add one (reverse proxy or
  application) before exposing registration publicly.
- There is no admin bootstrap command: every registered user is an `auditor`.
- The Nuclei binary is not in the backend image yet (the Nuclei integration is not built).
- Back up the `pgdata` volume; `reports` is a volume for generated report files.
