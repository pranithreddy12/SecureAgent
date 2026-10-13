# ADR-020: MCP trust layer, opt-in verdict recording, and the detector gaps it exposed

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "go, phase 1 then 2 then 3")
- **Relates to:** ADR-009 (MCP), ADR-017 (LLM review), ADR-019 (`explain_finding`)

## Context

Two OpenCode runs on the same project, with and without the MCP server, showed:
- the assistant inflated a low "XML entity expansion" item into XXE/SSRF/file disclosure and suggested an
  option that does not exist (`XMLParser(resolve_entities=...)`);
- it spent its effort re-reading code to dismiss false positives;
- the scanner missed a real hardcoded `SECRET_KEY` fallback;
- every `explain_finding` re-scanned the repository, and a scan returned up to 200 findings in one blob.

## Decision

**Phase 1 -- trustworthy and cheap.** Each finding type has hand-written guidance (`analysis/guidance.py`):
`impact_ceiling`, `not_claimed`, `verify_with`. Server `instructions` state the workflow and the rule
"never report above the ceiling". Scans return a severity-ordered page with filters and a cursor, per-type
counts and a `coverage` block. Scans are cached per (root, tree signature, options). `suggest_fixes` takes an
`id`.

**Phase 2 -- close the loop.** `record_verdict` writes a justified, optionally expiring suppression to
`secureagent-suppressions.json`. It is **off by default**, hidden from `tools/list` and refused unless
`SECUREAGENT_MCP_WRITE=1`, and confined to the allowed roots. A `security_review` prompt encodes the
workflow.

**Phase 3 -- the gaps.**
- `os.environ.get("X_SECRET", "<literal>")`, `os.getenv`, `process.env.X || "<literal>"` are reported
  (comments and docs are not).
- Dockerfile final stage as root, compose `user: root` / `privileged: true`, CSP `unsafe-inline` on
  script-src/default-src, bulk export/download endpoints that load a whole result set with no limit.
- Precision: a lookup into a module-level constant dict is not request data however the key is chosen; a
  call to a function defined in the same file is judged by what the function returns, not by receiving a
  tainted argument; `if col not in ALLOWED: col = "default"` validates `col`; a ternary is tainted by its
  branches, not its test.

## Not claimed

- Guidance text is human-written and short; it reduces inflation, it does not prevent it. No model run has
  been scored (the evaluation harness is still to do).
- The new detectors are heuristics checked on constructed cases and the project's own scan; their
  real-world precision is unmeasured. The constant-table rule is conservative (a name written anywhere else
  is not constant) but remains position-insensitive like the allow-list rule.
- `record_verdict` records an assistant's or user's judgement; it does not make the finding false.

## Consequences

- New env var `SECUREAGENT_MCP_WRITE`; new tool and prompt; new finding types
  (`container_runs_as_root`, `privileged_container`, `csp_unsafe_inline`, `unbounded_query`) and the
  "Hardcoded fallback for secret" rule, all with guidance.
- Existing baselines are unaffected (existing fingerprints are unchanged); new findings may appear.
