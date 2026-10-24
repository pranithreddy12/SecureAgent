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

## Day 2: frontend

`/targets` (register, list) and `/targets/{id}` (safety status, revalidate, authorization
checkbox, "Start live audit", audits list, delete) -- new pages, mirroring the existing
Projects pages' shape. `frontend/services/targets.ts` is a thin wrapper matching
`frontend/services/projects.ts`'s pattern. The audit detail page (`/audits/[id]`) now renders
`LIVE_STAGES` (the 8 live-pipeline stage names) instead of the source pipeline's 9 when
`audit.audit_type === "live"`; the findings/triage/suggest-fix panels needed zero changes since
live findings are already `Vulnerability` rows.

Fixed one more real bug surfaced by actually clicking through a live run: `_wrap()`'s success
branch logged the "completed" audit log but never wrote `audit.stage_state[stage]`, so the
frontend's per-stage checkmark (which reads `stage_state[key].completed_at`, the same field the
source pipeline writes) never lit up for live audits even though the stage had, in fact,
finished. One-line fix in `live_audit_service.py`.

Verified live, manually, end-to-end: registered a target at `http://host.docker.internal:8899/`
(a throwaway local HTTP server, cleaned up afterward), authorized it, started an audit, watched
all 8 stages complete in the UI in real time, and got 3 findings with `status: confirmed` --
"Mark as false positive" and "Suggest a fix" both worked unmodified. No new automated tests were
needed (the UI calls endpoints already covered by `test_targets.py`); frontend suite stayed at
42 passed, `tsc`/`eslint`/`next build` all clean.

## Day 3: real ZAP, two real bugs

Brought up the `pipeline` and `lab` compose profiles (`zap`, and OWASP Juice Shop as a throwaway,
deliberately-vulnerable local target allow-listed just for this) and ran `run_zap()` for real for
the first time. It failed twice, both genuine bugs in the untracked code, not environment issues:

1. **`_include_regex()` didn't allow a port.** ZAP's spider needs the target URL to match the
   scan's context include-regex or it refuses with `url_not_in_context`. The regex was built from
   `scope.allowed_hosts` (port-stripped, correctly, for the *authorization* scope check) but reused
   verbatim for ZAP's own URL-matching regex, which needs the literal URL including its port.
   `http://juice-shop:3000/` never matched `https?://(juice-shop)/.*`. Fixed by adding an optional
   `(:\d+)?` group.
2. **Attack strength was set *after* the scan started.** `run_zap()` called
   `ascan/action/scan/` and only then tried to lower the attack strength to LOW -- by which point
   ZAP had already queued every rule at its policy default (MEDIUM). One of those rules,
   `DomXssScanRule` (ZAP's "Client Browser" policy category), launches a headless browser per
   scan and OOM-killed the ZAP container outright (exit 137) -- twice, reproduced both times.
   Fixed by moving the attack-strength call before `ascan/action/scan/`, and, since a
   non-destructive low-strength scan has no business launching a browser at all, by turning the
   "Client Browser" category off entirely (`setPolicyAlertThreshold=OFF`) rather than just
   throttling it.

Verified clean after both fixes: a real low-strength ZAP scan (spider + active scan, LOW
strength, no browser rules) against Juice Shop completed in 131s with 200 genuine alerts (Cross-
Domain Misconfiguration, missing CSP, etc.), ZAP container stayed up the whole time. New
`tests/test_zap_tool.py::test_include_regex_matches_a_host_with_a_port` locks in fix #1 as a
regression guard (fix #2 isn't unit-testable without a real ZAP instance; it's covered by this
manual verification, consistent with how Nuclei's subprocess invocation is handled elsewhere in
this codebase). Full backend suite: 592 passed, 2 skipped.

## Not claimed

Resume-from-failed-stage for live audits (not attempted -- source audits have it, live audits
restart from scratch on retry), and the remaining untracked pieces (`workflows/audit_graph.py`'s
own `build_graph()`/`PROGRESS`-in-state design, superseded by this ADR's per-node persistence
approach) are not deleted, just unused by the wiring above. Nuclei was not exercised against a
real binary this session (no `nuclei` installed in the dev image); its `NucleiUnavailable`
graceful-degrade path was exercised instead, same as day 1.
