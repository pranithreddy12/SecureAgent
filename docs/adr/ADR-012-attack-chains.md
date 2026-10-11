# ADR-012: Attack chains as an interpretation layer over findings

- **Date:** 2026-10-11
- **Status:** Accepted
- **Extends:** ADR-008, ADR-010

## Context

A flat findings list hides how weaknesses combine: an injection behind a missing auth check is
reachable by anyone, while the same injection behind a login is not. Developers need to know what to
fix first, not just what exists.

## Decision

`app/analysis/chains.py` derives **attack chains** from the unified findings plus the extracted
routes. Rules (deterministic, structural):

| Chain | Members |
|---|---|
| Unauthenticated execution/injection | route with no visible guard + a sink finding inside that handler (SQL/command/code injection, SSRF, path traversal, insecure deserialization) |
| Unauthenticated record access | unguarded route + IDOR finding in that handler |
| Anonymous privilege escalation | unguarded route + mass assignment / client-trusted privilege in that handler |
| Cross-site request abuse | credentialed wildcard CORS + CSRF protection disabled |

A finding belongs to the route whose definition most closely precedes it in the same file (the next
route bounds the handler). Each chain carries ordered steps, its members, a **fix-first**
recommendation, and explicit **assumptions** (e.g. no global middleware, which static analysis
cannot see).

Honesty rules:
- A chain is not a finding: it has no status, is excluded from baselines and `--fail-on`, and never
  changes a finding's severity.
- A chain's severity is its **worst member's** severity. It is never escalated (an earlier draft
  bumped unauthenticated chains one level; every demo chain became CRITICAL, which inflated and
  flattened the ranking).
- Chains are only produced when all members are present.

## Alternatives

- **LLM-written narratives** -- not reproducible and can invent links; may later *phrase* these
  deterministic chains but not discover them.
- **Full data-flow / attack-graph engine** -- far larger; this covers the common structural cases.

## Consequences

- Handler attribution is line-based (route def to next route def); handlers split across files or
  using non-route entry points are not chained.
- New chain rules are added in one place and must state their assumptions.
