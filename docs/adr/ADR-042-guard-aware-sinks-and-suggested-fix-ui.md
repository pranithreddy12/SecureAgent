# ADR-042: A guard-aware structural rule, and a "suggest a fix" panel in the UI

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "i think we need a fix for the issues / recommend fixed code
  snippet in the ui", after asking why the honestly-low-confidence `static:sinks` SQL findings
  were still shown next to the ADR-040/041 fixes)

## Context

Two separate, smaller asks from the same conversation:

1. The remaining `medium`/`suspicious` SQL findings in the owner's project are the *structural*
   detector (`app/analysis/sinks.py`), which has no taint context at all -- it flags any
   f-string/`%`/`+`-built query passed to `execute()` regardless of whether the taint engine has
   already proven the interpolated name safe (ADR-040/041's `_cfg`/`parse_sort` guards). That is
   real, avoidable noise in the cases the structural rule can actually see.
2. The web app showed a `remediation` sentence per finding, but not the deterministic, verified
   patch engine (`app/analysis/fixes.py`, ADR-013) that `secureagent fix` and the MCP's
   `suggest_fixes` already exposed -- it was never wired into the browser.

## Decision

**Guard-aware structural SQL rule:** `sinks.py`'s `_SinkVisitor` now computes, per function,
`taint._allowlist_guarded(func, ctx)` (reusing ADR-040/041's logic directly, not reimplementing
it) and threads it into `_builds_sql_string` as `guarded`. A JoinedStr/BinOp part built entirely
from a guarded name (`_is_guarded_value`) no longer counts toward the rule firing. This covers the
same-function and one-hop-via-a-validator-call cases the taint engine covers. It does **not** cover
a parameter validated only by its *caller* two frames up (e.g. `compute_stats(name)` where `name`
was validated in `listing`, not in `compute_stats` itself) -- that needs the structural rule to be
interprocedural the way the taint engine is, which this change does not attempt.

**"Suggest a fix" in the UI:** `GET /audits/{id}/findings/{finding_id}/fix`
(`SuggestedFix` schema) calls a new `fixes.suggest_fix_for(root, endpoint, type)` -- `propose_fixes`
for exactly one finding, duck-typed rather than requiring a full `ReportFinding`. Most finding
types (anything data-flow-shaped: injection, access control, business logic) have no deterministic
fixer and the response says so plainly (`available: false`) rather than fabricating a plausible
snippet. The finding types that do (`weak_hash`, `hardcoded_secret`, `debug_enabled`,
`csrf_disabled`, `jwt_verification_disabled`, `insecure_deserialization`/yaml) get the real,
already-verified unified diff, its description and caveat. The frontend
(`SuggestedFixPanel`, `audits/[id]/page.tsx`) fetches this lazily on a "Suggest a fix" click, not
on page load.

## Verification

- Structural rule: new tests in `tests/test_realworld_fp.py` for the same-function guarded case
  and its still-flagged unguarded counterpart.
- API: new test in `tests/test_audits.py` against the existing `VULN_APP` fixture (has both a
  `weak_hash` and a `sql_injection` finding) -- asserts a verified diff for one, `available: false`
  for the other, 404 for an unknown finding id.
- Frontend: 2 new Vitest cases (fix available / not available), `tsc`/`eslint`/`next build` clean.
- **Watched it live, not just the tests**: rebuilt the Docker stack, ran a real audit against a
  two-finding fixture through the actual web app, clicked "Suggest a fix" on both findings, and
  screenshotted the real result -- a genuine unified diff for the weak-hash finding, and "No
  automatic fix for this finding type yet" for the SQL injection one.
- Full backend suite: 580 passed, 2 skipped. Benchmark unchanged 97%/97%.

## Not claimed

The structural-rule fix does not reach the "validated two frames up" pattern still present in the
owner's real project (3 of its remaining findings); making the structural rule fully
interprocedural is a larger change, not attempted here. The suggested-fix feature surfaces an
*existing*, already-verified capability -- it adds no new automatic rewrites and does not touch
`FIXERS`'s scope.
