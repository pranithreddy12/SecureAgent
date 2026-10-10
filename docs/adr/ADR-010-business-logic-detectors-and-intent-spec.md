# ADR-010: Deterministic business-logic detectors and a developer intent spec

- **Date:** 2026-10-10
- **Status:** Accepted
- **Extends:** ADR-008 (grey-box business-logic analysis), ADR-009 (dependency-light scanner)

## Context

ADR-008 committed to finding logic flaws using source code plus developer intent, but the
engine so far only covers classic patterns (injection, IDOR, missing authz). Two realistic
logic-flaw families were unbuilt: **the server trusting values the client controls**
(price, role, `is_admin`, mass assignment) and **developer-declared rules** ("only owners
read orders") that no generic scanner can know.

## Decision

1. **`app/analysis/business_logic.py`** — deterministic Python-AST detectors, handlers only,
   request-source taint only (path params and validated schema bodies are *not* treated as
   attacker-shaped, which keeps false positives down):
   - `mass_assignment` (CWE-915): `Model(**request.json)`, `obj.update(**data)`, `setattr`
     loop over request items.
   - `client_trusted_privilege` (CWE-269): `role`/`is_admin`/`permissions`... assigned or
     passed from request data.
   - `client_trusted_value` (CWE-602): `price`/`amount`/`total`/`discount`... taken from the
     client instead of server-side data.
2. **Intent spec** — `secureagent-intent.json` in the repo root (or `--intent PATH`).
   JSON, not YAML, because the installable scanner depends only on stdlib + jinja2 + pydantic
   (ADR-009). Rule types, evaluated against the extracted Application Model:
   - `require_auth` — routes matching `paths` globs must show an authorization guard.
   - `owner_scoped` — matching routes must not look up records by request id without
     ownership scoping (reuses the IDOR analysis).
   - `never_from_client` — listed field names must never be set from request data (extends the
     detector vocabulary above with project-specific fields).
3. **Honesty model unchanged.** Findings are `suspicious`, never `confirmed`; an intent
   violation says which developer rule it violates and what evidence was (not) found.
   Nothing is executed; the analysis is read-only.

## Alternatives

- **YAML spec** — nicer to write, but adds PyYAML to the installable scanner (violates ADR-009).
  A YAML front-end can be added behind an optional extra later.
- **Natural-language rules interpreted by an LLM** — non-deterministic and not reproducible;
  deferred as an optional front-end that must compile to this JSON.

## Consequences

- Python only for the new detectors (JS/TS logic detectors are future work).
- Static: global middleware or serializers outside the handler can neutralise a flagged
  pattern, so every finding stays a review item with an explicit reason.
- A malformed spec fails loudly (exit code 2) instead of silently scanning without it.
