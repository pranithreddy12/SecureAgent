# SecureAgent – Deployment

What can be deployed **today**: the web application skeleton (Next.js frontend with
register/login/dashboard/settings, FastAPI backend with authentication and health endpoints,
PostgreSQL with migrations) and the `secureagent` command-line scanner. The audit pipeline
(targets → recon → ZAP/Nuclei → agents) is **deferred by decision (ADR-014)**, so the `zap` and
`juice-shop` services are defined but not started by default (`--profile pipeline` / `--profile lab`).

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
| `zap` | OWASP ZAP daemon, profile `pipeline` — *deferred; not used by the backend* | internal only |
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
| `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL` | Optional; powers the opt-in `ai_review`/`ai_validator`/`ai_narrative` pipeline stages and `secureagent review`. `LLM_PROVIDER` is `anthropic` (default) or `mistral`; empty `LLM_MODEL` picks that provider's default. See [docs/MANUAL.md §5](MANUAL.md#5-the-opt-in-ai-layer-providers). |

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
- Failed sign-ins are throttled in-process (5 per 15 minutes per address+email, 429 with `Retry-After`);
  add a reverse-proxy limit as well before exposing registration publicly.
- Registration always creates an `auditor`; create administrators with `python -m app.manage create-admin`.
- The Nuclei binary is not in the backend image yet (the Nuclei integration is not built).
- Back up the `pgdata` volume; `reports` is a volume for generated report files.

## Source audits (web app)

The web app analyses code that is **mounted into the backend container**, never arbitrary host paths.

1. Put the project under `./workspace` (git-ignored), e.g. `./workspace/my-app`.
2. `docker compose up --build` (compose mounts it read-only at `/workspace` and sets
   `SOURCE_ROOTS=/workspace`).
3. In the UI: **Audits -> New source audit**, path `/workspace/my-app`, tick the authorization
   statement, start. Progress, findings, the activity log and the HTML/PDF report appear on the audit page.

Outside Compose, set `SOURCE_ROOTS` to a comma-separated list of absolute directories; an empty value
disables the feature (the API answers 503). Paths are resolved (symlinks and `..` included) and must be
inside a root. The directory is only read.

## Uploading a zip instead

Set `UPLOAD_DIR` (Compose does: a named volume at `/app/uploads`). **Projects -> Upload a zip** then
unpacks the archive into a private per-user folder, audits it like any other project and deletes it when the
project is deleted. Limits: `MAX_UPLOAD_MB` (25), `MAX_UPLOAD_FILES` (5000), `MAX_UPLOAD_UNPACKED_MB`
(150). Hostile archives (path traversal, symlinks, bombs, encryption) are refused. `SOURCE_ROOTS` may be
empty when only uploads are wanted. Keep `UPLOAD_DIR` outside `SOURCE_ROOTS`. See ADR-019.

## First administrator

Registration always creates an `auditor`. Create or promote an administrator from the server:

```bash
# in the backend container, or locally with the project virtualenv
SECUREAGENT_ADMIN_PASSWORD='choose-a-strong-passphrase' \
  python -m app.manage create-admin --email you@example.com --name "Your Name"
```

The password is read from `SECUREAGENT_ADMIN_PASSWORD` or prompted for; it is never a command-line
argument. If the email already exists the account is promoted and its password is left unchanged.
