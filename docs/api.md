# SecureAgent – REST API Design

Status: **Partially implemented** — health, `/api/auth/*` and the **source-audit** endpoints below are
implemented; the target and live-audit endpoints in the full table are still design only.

**Implemented source-audit API (ADR-011)** -- all owner-scoped (another user's audit is a 404):

| Method | Path | Purpose |
|---|---|---|
| POST | /api/audits/source | `{path, label?, authorization_confirmed, exclude[]}` -> 202; 400 without confirmation or for a path outside `SOURCE_ROOTS`; 503 if `SOURCE_ROOTS` is unset |
| POST | /api/audits/{id}/retry[?resume=true] | Re-run a **failed** source audit: clean slate, or `resume=true` to continue from the failed stage (409 otherwise; owner only) |
| POST | /api/projects | Register a source project (path under `SOURCE_ROOTS`; limit per user) |
| GET | /api/projects, /api/projects/{id} | List / detail incl. authorization history |
| POST | /api/projects/{id}/authorize, /revoke | Append an authorization / revocation record |
| POST | /api/projects/{id}/audits | Start an audit (403 without a current authorization; 429 over the concurrency limit) |
| GET | /api/projects/{id}/audits | The project's audits |
| DELETE | /api/projects/{id} | Delete the project (its audits are kept, unlinked) |
| GET | /api/audits | Own audits, newest first |
| GET | /api/audits/{id} | Status, stage state, severity counts, `attack_chains` |
| GET | /api/audits/{id}/findings | Persisted findings |
| GET | /api/audits/{id}/logs | Activity log |
| GET | /api/audits/{id}/report?format=html\|pdf&download= | Report (CSP-locked HTML, or PDF where Pango is available) |

The design table below describes the *full* target-based API; `POST /api/audits {target_id}`,
`/start`, `/stop` and `/status` do not exist.
 Base path `/api`. JSON. OpenAPI docs at `/docs`.

Authentication: JWT (HS256, `SECRET_KEY`) issued on login, returned in an httpOnly,
`SameSite=Lax` cookie (`Secure` when `COOKIE_SECURE=true`). `Authorization: Bearer`
is also accepted (API clients, tests). All endpoints except register/login/health
require authentication. Users only see their own resources; `admin` sees all.

Errors: `{"detail": "..."}` with proper status codes (400 validation, 401, 403 —
including missing target authorization, 404 — also for other users' resources,
409 conflict, 422, 429 limit reached).

| Method | Path | Purpose |
|---|---|---|
| GET | /api/health | Liveness + `demo_mode`, tool availability (ZAP/Nuclei/LLM) |
| POST | /api/auth/register | Create user (name, email, password ≥ 10 chars) |
| POST | /api/auth/login | Issue token cookie + body |
| POST | /api/auth/logout | Clear cookie |
| GET | /api/auth/me | Current user |
| POST | /api/targets | Create target (runs safety validation, enforces `MAX_TARGETS_PER_USER`) |
| GET | /api/targets | List own targets |
| GET | /api/targets/{id} | Target + latest authorization + validation result |
| PUT | /api/targets/{id} | Update; URL/scope change resets authorization |
| DELETE | /api/targets/{id} | Delete (blocked while an audit is running) |
| POST | /api/targets/{id}/validate | Re-run safety/scope validation (+) |
| POST | /api/targets/{id}/authorize | Body `{confirmed: true, statement}` → AuthorizationRecord |
| POST | /api/audits | Create audit `{target_id, demo?}` (status `queued`) |
| GET | /api/audits | List (filter by target/status) |
| GET | /api/audits/{id} | Detail |
| POST | /api/audits/{id}/start | Start, or resume a failed audit |
| POST | /api/audits/{id}/stop | Cancel running audit |
| GET | /api/audits/{id}/status | `{status, current_stage, progress, stages[], started_at, elapsed}` |
| GET | /api/audits/{id}/logs | Audit log entries (`?after=<timestamp>` for incremental polling) |
| GET | /api/audits/{id}/findings | Findings with filters: severity, status, owasp, min_confidence, endpoint |
| GET | /api/findings | All own findings, same filters + `audit_id` (+) |
| GET | /api/findings/{id} | Finding detail |
| GET | /api/audits/{id}/report | Report metadata + HTML |
| GET | /api/audits/{id}/report/download?format=pdf\|html | File download |
| GET | /api/dashboard/summary | Counts, severity/status/OWASP distributions, recent audits/findings/activity |
| GET | /api/activity | Recent audit log entries across own audits (+) |

(+) = additions beyond the brief, required by the frontend pages (`/findings`,
`/activity`) or target validation flow.
