# ADR-006: Authentication — Argon2id + JWT in httpOnly cookie

- **Date:** 2026-10-03
- **Status:** Accepted

## Context
The brief requires password hashing, JWT or secure sessions, protected endpoints,
logout and a current-user endpoint, with no plaintext passwords or hardcoded secrets.
The frontend proxies `/api/*` (same origin), so cookies are first-party.

## Decision
- Passwords: Argon2id via `argon2-cffi` (library defaults). Login always runs one
  hash verification (dummy hash for unknown emails) to avoid a user-enumeration
  timing oracle; both failure cases return the same 401 message.
- Tokens: HS256 JWT via `PyJWT`, signed with `SECRET_KEY` (≥ 32 chars, env only),
  claims `sub`, `iat`, `exp` (all required), expiry `ACCESS_TOKEN_EXPIRE_MINUTES`.
  Algorithm pinned on decode (rejects `alg=none`).
- Transport: `access_token` cookie — `HttpOnly`, `SameSite=Lax`, `Secure` when
  `COOKIE_SECURE=true`. `Authorization: Bearer` also accepted (API clients, tests).
- Logout clears the cookie. Tokens are stateless; no server-side revocation list.
- Registration always creates role `auditor`; the `role` field in requests is
  ignored. `require_admin` dependency exists for admin-only endpoints.
- CSRF: SameSite=Lax blocks cross-site cookie sending on POST/PUT/DELETE, and the
  API only accepts JSON bodies; no separate CSRF token.

## Alternatives
- passlib/bcrypt — passlib is unmaintained; bcrypt truncates at 72 bytes.
- Server-side sessions table — enables revocation, but adds a DB lookup per request
  and a cleanup job; unnecessary for this project's threat model.
- localStorage tokens — exposed to XSS; rejected.

## Consequences
- A stolen token stays valid until expiry (default 60 min).
- No admin bootstrap path yet (see PROJECT_MEMORY open issues).
