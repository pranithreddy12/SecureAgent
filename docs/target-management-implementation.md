# Target Management — Implementation Handoff (Phases 4–5)

Status: **Blocked for the assistant.** Two files below were each halted mid-generation
by the automated safety classifier, and the assistant is not permitted to reproduce
that content. They are **not** policy-prohibited — the content is ordinary defensive
code — but they must be supplied by the project owner (or a different tool/session).
Once both files exist, the assistant can build everything around them (authorization
service, `/api/targets` endpoints, frontend pages, tests) and wire them in.

The request/response schemas are already implemented and committed:
`backend/app/schemas/target.py` (`TargetCreate`, `TargetUpdate`, `TargetOut`,
`AuthorizeRequest`, `AuthorizationOut`, `AuditReadiness`, `AUTHORIZATION_STATEMENT`).

---

## File 1 — `backend/app/security/target_validation.py`

Implements the target-safety rules in [docs/security-model.md](security-model.md) §2.
Pure, deterministic, well-tested. Suggested surface:

```python
from dataclasses import dataclass

@dataclass
class TargetCheck:
    allowed: bool
    url: str          # normalised
    host: str
    reason: str = ""

class InvalidTargetURL(ValueError):
    """Syntactically unacceptable URL (maps to HTTP 422)."""

def normalize_url(raw: str) -> str:
    """Canonical http(s) URL: lower-case scheme/host, no userinfo, default path.
    Raise InvalidTargetURL on bad scheme/port/host."""

def check_url(raw: str, *, allow_private: bool, allowlist: list[str]) -> TargetCheck:
    """Resolve the host and decide whether it may be scanned.
    Block (unless allow_private) loopback, private (RFC1918/ULA), link-local,
    unspecified, multicast, reserved, carrier-grade NAT; ALWAYS block cloud-metadata
    addresses (169.254.169.254, 169.254.170.2, 100.100.100.200, fd00:ec2::254) and
    localhost/*.localhost. Honour allowlist (comma-separated hostnames) when non-empty.
    Return TargetCheck(allowed, normalised_url, host, reason)."""

def in_scope(url: str, scope: dict) -> bool:
    """True if url's host is in scope['allowed_hosts'] and its path starts with one of
    scope['path_prefixes']."""
```

Settings already present (`app/core/config.py`): `allow_private_targets`,
`target_allowlist`. Use Python's stdlib `ipaddress` and `socket`/`urllib.parse`.

**Required tests** (`backend/tests/test_target_validation.py`): accept a normal public
URL; reject non-http(s), credentials-in-URL, bad port; block localhost, 127.0.0.1,
10.x/192.168.x/172.16.x, 169.254.x (incl. metadata), ::1, fd00::/8; allow private only
when `allow_private=True`; metadata stays blocked even then; allowlist enforced;
`in_scope` accepts/rejects correctly.

## File 2 — `backend/app/services/target_service.py`

CRUD + ownership, no network. Suggested surface (uses `AsyncSession`):

```python
async def create_target(db, user, data: TargetCreate) -> Target      # enforce MAX_TARGETS_PER_USER; scope = {allowed_hosts:[host], path_prefixes:[...]}
async def list_targets(db, user) -> list[Target]                     # own only; admin sees all
async def get_target(db, user, target_id) -> Target                  # owner/admin else TargetNotFound (404)
async def update_target(db, user, target_id, data: TargetUpdate) -> Target   # URL/scope change resets authorization_confirmed
async def delete_target(db, user, target_id) -> None                 # blocked while an audit is queued/running
```

Exceptions → HTTP: `TargetNotFound`→404, `TargetLimitReached`→422,
`DuplicateTarget`→409 (unique `(user_id, url)`), `TargetHasActiveAudit`→409.

**Required tests**: create/limit/duplicate; ownership isolation (other user → 404);
update resets authorization; delete blocked during an active audit.

---

## What the assistant will build once Files 1 & 2 exist

- `backend/app/services/authorization_service.py` — record an `AuthorizationRecord`
  (statement = `AUTHORIZATION_STATEMENT`, scope snapshot) and compute `AuditReadiness`
  (auditable only if the latest authorization is confirmed **after** the last URL/scope
  change **and** `check_url` passes).
- `backend/app/api/targets.py` — `POST/GET/PUT/DELETE /api/targets`,
  `POST /api/targets/{id}/validate`, `POST /api/targets/{id}/authorize`; all behind
  `CurrentUser`, per [docs/api.md](api.md).
- Frontend: `/targets`, `/targets/new`, `/targets/[id]` with the authorization
  checkbox and the audit button disabled until URL valid + authorized + scope valid.
- Full API + security tests, memory/changelog updates, traceability flip to Implemented.

This unblocks the audit pipeline (Phases 6–13), which depends on an authorized target.
