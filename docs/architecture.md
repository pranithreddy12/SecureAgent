# SecureAgent – System Architecture

Status: **Design (Phase 0)** — describes the target architecture. Sections are marked
as implemented in `PROJECT_MEMORY.md` as phases complete. Diagrams must always match the
actual code; update this file when the code diverges.

## 1. System Context

```
                 ┌────────────────────────────┐
  Browser ─────► │ frontend (Next.js / React) │
                 └─────────────┬──────────────┘
                               │ REST /api/* (JWT in httpOnly cookie)
                 ┌─────────────▼──────────────┐
                 │ backend (FastAPI)          │
                 │  api → services → models   │
                 │  audit runner (bg tasks)   │
                 │  LangGraph workflow        │
                 │   └ agents → tools         │
                 └──┬─────────┬─────────┬─────┘
                    │         │         │
          ┌─────────▼──┐ ┌────▼─────┐ ┌─▼──────────────┐
          │ postgres   │ │ zap      │ │ nuclei binary  │
          │ (SQLAlchemy│ │ (daemon, │ │ (in backend    │
          │  + Alembic)│ │  REST API│ │  image, argv   │
          └────────────┘ └────┬─────┘ │  subprocess)   │
                              │       └───────┬────────┘
                              ▼               ▼
                     AUTHORIZED TARGET (scope-checked)
                              ▲
                  optional LLM provider (LangChain chat model)
```

## 2. Backend Layering

| Package | Responsibility |
|---|---|
| `app/core` | Settings (pydantic-settings), DB session, structured logging, security primitives (hashing, JWT) |
| `app/models` | SQLAlchemy ORM models |
| `app/schemas` | Pydantic request/response models and agent I/O contracts |
| `app/api` | FastAPI routers — thin; delegate to services |
| `app/services` | Business logic: users, targets, authorization, audits, findings, reports, dashboard |
| `app/security` | Target safety validation (URL, DNS, IP ranges, scope, allowlist) |
| `app/tools` | Controlled tools: recon, ZAP, Nuclei, validation HTTP probes, target validation. Every tool re-checks authorization + scope and enforces timeouts / output limits |
| `app/agents` | Reconnaissance, Vulnerability Scanner, Safe Validation, Validator, Report agents |
| `app/workflows` | LangGraph `AuditState`, graph definition, audit runner |
| `app/reports` | Jinja2 HTML templates + PDF rendering |
| `app/demo` | Demo-mode fixtures and simulated tool adapters |

Rule: **agents never execute anything directly** — they call tools; tools enforce policy.

## 3. Background Execution

See ADR-005. Audits run as `asyncio` tasks launched by the API process (not in the
request thread). All progress is persisted to PostgreSQL after every stage, so the
frontend polls `GET /api/audits/{id}/status` and `/logs`. A concurrency semaphore
enforces `MAX_CONCURRENT_SCANS`. Stop = cancellation flag + task cancel + subprocess
kill. On API restart, audits left `running` are marked `failed` with
"interrupted" and can be retried from their last completed stage.

Redis/Celery are deliberately **not** used initially (documented in ADR-005).

## 4. AI Usage

The LLM is optional and never the source of truth:

- Inputs: structured tool observations (Pydantic). Outputs: Pydantic-validated
  structured output; invalid output → deterministic fallback.
- Used for: prioritisation notes, explanations, false-positive reasoning notes,
  remediation wording, executive summary.
- The Validator's status decision is computed deterministically from evidence; the
  LLM may add reasoning text but may not upgrade a status beyond what evidence
  supports (e.g. cannot mark `confirmed` without a positive validation result).
- If `LLM_API_KEY` is unset or the call fails → deterministic templates are used and
  the report states "AI narrative unavailable; deterministic summary used."

## 5. Frontend Architecture

Next.js (App Router) + TypeScript + Tailwind. Dark security theme.

```
frontend/
  app/            routes: login, register, dashboard, targets, targets/new,
                  targets/[id], audits, audits/[id], findings, findings/[id],
                  reports/[id], activity, settings
  components/     layout (sidebar, topbar), ui (card, badge, table, button),
                  charts, audit (pipeline, agent activity, timeline), findings
  hooks/          useAuth, usePolling
  lib/            fetch wrapper (credentials: include), formatters, severity colours
  services/       typed API clients per resource
  types/          API types mirroring backend schemas
```

- Auth: httpOnly cookie set by backend; Next.js middleware redirects unauthenticated
  users to `/login` for protected routes.
- Progress: polling every 2 s while an audit is `queued`/`running`.
- Charts: one small chart library (Recharts) — decided at Phase 14.
- Demo-mode banner shown globally when backend reports `demo_mode: true` and on every
  demo audit/report.

## 6. Docker Architecture

`docker-compose.yml` services:

| Service | Image | Purpose |
|---|---|---|
| `postgres` | `postgres:16` | Database (named volume) |
| `zap` | `zaproxy/zap-stable` | ZAP daemon, API key from env, API reachable only on the compose network |
| `backend` | `docker/backend.Dockerfile` (Python + Nuclei binary) | FastAPI + workflow; runs `alembic upgrade head` on start |
| `frontend` | `docker/frontend.Dockerfile` | Next.js |
| `juice-shop` *(profile `lab`)* | `bkimminich/juice-shop` | Intentionally vulnerable local target for genuine testing |

Only `frontend` and `backend` publish ports to the host. Reports volume mounted at
`/app/reports`.

## 7. Extensibility for Continuous Testing (not implemented)

`SecurityAudit` creation is a service call independent of HTTP, so a scheduler or
CI webhook can later create + start audits. Nothing else is built for this until
required (see `PROJECT_MEMORY.md` §20).
