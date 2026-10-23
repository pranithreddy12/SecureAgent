# ADR-044: Option 2 resumed -- the live-target pipeline, day 1

- **Date:** 2026-10-24
- **Status:** Accepted (owner: "i think i need this project in a meaning full way / do
  something and i want new plan", then explicitly: finish the live pipeline, reuse the
  untracked files, scoped to a few days)

## Context

ADR-014 (2026-10-11) closed the project as a grey-box static security auditor and explicitly
deferred the original brief's live multi-agent pipeline (Option 2), blocked on two files the
owner was going to supply. Between then and now, 19 untracked files appeared in the working tree
-- `app/agents/`, `app/tools/`, `app/workflows/`, `app/security/target_validation.py`,
`app/services/target_service.py`, `app/services/authorization_service.py`,
`app/schemas/pipeline.py`, `app/demo/adapters.py` -- from a concurrent session attempting exactly
this. A standing instruction told this session never to read, edit or commit them. The owner
lifted that instruction today.

## What was actually there

Not abandoned scaffolding -- a **nearly complete, safety-conscious implementation** of Option 2's
B1-B4 (`docs/PROJECT_CLOSEOUT.md` §5B): real SSRF defenses (`security/target_validation.py`:
cloud metadata IPs/hostnames, private/loopback/CGNAT ranges, credentials-in-URL rejection, DNS
resolved after the allow-list check), a defence-in-depth `inspect_url()` gate every outbound call
re-checks, ZAP via its REST API, Nuclei via `subprocess.run(shell=False)` with an argv list and
DoS/intrusive tags excluded, genuinely non-destructive evidence collection (inert markers, no
exploit payloads), a complete gated LangGraph-shaped workflow, and an offline demo mode. The `Target`
/ `AuthorizationRecord` DB models, schemas and settings were already tracked and migrated from the
original scaffolding -- only the API layer, a persisting runner, and tests were missing, and B5
(a frontend) didn't exist at all.

## Decision (day 1 of 3)

Wire it end to end, backend only, scoped down from the full B1-B5 list to one real live-scan path:

- `app/services/live_audit_service.py`: a live-audit runner that wraps the untracked agents
  (`app/agents/*`) and the untracked gate functions (`workflows/audit_graph.py`'s
  `authorization_check`/`target_validation`/`attack_surface_processing`/`_after_gate`/
  `_after_scan`, reused unchanged) with **per-stage DB persistence**, mirroring
  `app/pipeline/graph.py`'s pattern for the source pipeline exactly -- not
  `workflows/audit_graph.py`'s own `build_graph()`, which keeps progress in memory only and would
  leave the UI showing nothing until the whole run finished (a live scan can take minutes).
  `graphlib.py` gained an optional `on_step` hook for the same reason, though it turned out moot:
  `langgraph` is an installed dependency, so the *real* `StateGraph` compiles the graph, not the
  dependency-free fallback -- the per-stage persistence instead lives in each node's own wrapper
  closure, the same way the source pipeline does it.
- `app/api/targets.py`: register/list/get/update/delete, authorize, readiness, start-audit,
  list-audits -- mirrors `app/api/projects.py`'s shape exactly.
- Live findings are written into the **same** `Vulnerability`/`SecurityReport` tables the source
  pipeline uses (`FinalFinding` maps onto `Vulnerability` field for field), so
  `/api/audits/{id}`'s existing findings/logs/report endpoints work for a live audit unchanged --
  nothing new to build there.
- `app/api/audits.py`'s background launcher now dispatches on `audit_type` to
  `live_audit_service.run_live_audit` or the existing `audit_service.run_source_audit`.
- Fixed one real bug the first real exercise of this code found: `validator_agent.decide()`
  passed `confidence` both via `**finding.model_dump()` and as an explicit kwarg
  (`FinalFinding(**finding.model_dump(), confidence=..., ...)`), a `TypeError` on every single
  finding. Never caught before because this code had never actually been run.

## Verification

Not a demo-mode-only smoke test. `tests/test_targets.py::test_live_audit_runs_end_to_end...`
spins up a real `ThreadingHTTPServer` on loopback (no fixture faking), runs a real audit against
it through the actual API (`ALLOW_PRIVATE_TARGETS=true`, no ZAP key, no Nuclei binary -- both
degrade gracefully and are logged, exactly as they would in any environment without them
configured), and asserts genuine findings (missing security headers, found by the passive
checker) with **`status: confirmed`** -- reproduced by a real, non-destructive HTTP re-fetch. This
is the first finding this project has ever honestly been able to call confirmed; the static
pipeline has correctly never claimed it. 6 new tests (auth required, private-target rejection,
credentials-in-URL rejection, authorization gating, the end-to-end run, owner isolation). Full
backend suite: 591 passed, 2 skipped.

## Not claimed

Frontend (day 2), real ZAP verified live (day 3; only degraded-path tested so far, since ZAP needs
its own container), resume-from-failed-stage for live audits (not attempted -- source audits have
it, live audits restart from scratch on retry), and the remaining untracked pieces
(`workflows/audit_graph.py`'s own `build_graph()`/`PROGRESS`-in-state design, superseded by this
ADR's per-node persistence approach) are not deleted, just unused by the wiring above.
