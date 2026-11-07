# ADR-046: Ten research-driven features (exploit intel, supply chain, AI-app checks, BOLA, specs)

- **Date:** 2026-11-07
- **Status:** Accepted (owner: "proceed with all" after a feature-research pass)

## Context

A research pass (vendor tools, OWASP LLM / Agentic / MCP Top 10, IRIS (ICLR 2025), Unit 42
BOLABuster, KEV/EPSS practice) against the project's own known gaps -- ~50% recall on unseen apps,
regex JS engine, no confirmed live access-control findings, no exploit context for dependencies,
Nuclei never run -- produced ten recommendations. All ten were requested.

## Decision

Each feature keeps the project's rules: deterministic results, the LLM never decides, nothing
"confirmed" without live evidence, every outbound call opt-in or on the existing OSV switch.

| # | Feature | Where | Honesty boundary |
|---|---|---|---|
| 1 | Two-account BOLA check on live targets | `tools/access_check.py`, `agents/access_control_agent.py`, stage `access_control_check`, `POST /targets/{id}/audits` body, target page form, audit page card | GET only through the existing policy gate; credentials in memory only, never persisted or quoted; bodies compared by hash/similarity; only "B receives A's object" is a (confirmed) finding |
| 2 | AI-suggested taint specs (IRIS-style) | `analysis/taint_specs.py`, `secureagent specs`, engine hooks in `taint.py` | only names/signatures sent; invented names dropped; proposal written to `secureagent-taint.json` for human review; scans read the file, never the model |
| 3 | LLM / agent app checks | `taint.py` (`_mark_llm_calls`, `_is_tool`, `prompt_injection`), `misconfig.py` (MCP config, browser LLM keys) | LLM output is a taint *source* (LLM05); request data in system/developer prompts is `prompt_injection` (LLM01, suspicious); MCP/agent tool args are untrusted |
| 4 | KEV + EPSS + import reachability | `analysis/exploit_intel.py`, `analysis/reachability.py`, `DependencyFinding.priority` | severity never changed; priority is a separate label; "not imported" may still be transitive and never hides a finding |
| 5 | Malicious / typosquat / unregistered packages | OSV `MAL-` ids, `analysis/supply_chain.py` | malicious = critical (OSV says so); typosquat and registry-404 are suspicious (private registries 404 too) |
| 6 | AI-written fixes, verified | `fixes.verify_ai_fix`, `secureagent fix --ai`, web "suggest a fix" | same verification as deterministic fixers (applies exactly once, parses, re-scan shows finding gone, nothing new); unverified patches are never written |
| 7 | tree-sitter JS/TS engine | `analysis/js_ast.py`, `secureagent[js]` extra, Docker image | adds findings to the regex engine's, never removes one |
| 8 | Evaluation | benchmark re-run; held-out recall re-measured on fresh clones (see Evidence) | -- |
| 9 | Nuclei for real + live resume | Dockerfile (pinned v3.4.2, sha256-checked), `nuclei_templates`, partial output on timeout; live `stage_state[stage].output` + resume | gates always re-run on resume; stages after a failed stage no longer run |
| 10 | Opt-in secret liveness | `analysis/secret_verify.py`, `scan --verify-secrets` | off by default; GitHub/Slack/Stripe identity endpoints only; `live` -> confirmed, `revoked` -> informational |

## Evidence

- Backend 712 passed / 2 skipped (was 661); frontend 47 Vitest (was 43); lint no worse than before.
- Benchmark unchanged at 98% precision / 98% recall.
- BOLA: end-to-end live audit against a local server with a planted bug -> exactly one
  `confirmed` `bola` finding; the owner-checked object is "enforced"; no credential in the audit JSON.
- Nuclei, first real run (inside the rebuilt image, local throwaway server): found 2 genuine
  high alerts (`.env` disclosure). Two real bugs found and fixed: the full template set cannot finish
  within the 300 s cap at 5 req/s, and on timeout **all** results were discarded. Even the reduced
  default template set still reaches the cap at 5 req/s; results are partial but kept.

- **Held-out recall (35 apps, 361 planted flaws, fresh clones at the pinned commits):** code before
  this ADR 274/361 (75.9%; the "273" in earlier notes was stale); new code without the `js` extra
  274/361; with it **275/361 (76.2%)** -- the planted SSRF in vulnerable-node `sast/seeds/ssrf-fetch.js:7`.
  Across the 35 apps the new code adds exactly two findings over the old code, both genuine SSRF (that
  one, and skf-labs `nodeJs/RFI/app.js:23`, a user-supplied filename into `http.get`); no new finding
  in any clean file or fixed directory. Juice Shop: 4 score-board UI files could not be checked out
  (Windows path length); none is on the truth list.
- **Typosquat rule tightened by that measurement.** A plain edit-distance-1 rule flagged three
  legitimate packages (grequests ~ requests, djongo ~ django, scapy ~ scipy). The rule now counts only
  typing slips -- adjacent transposition, a doubled letter, a dropped non-first letter -- and those three
  are regression-tested.

## Not done / limits
- **Human labels:** the labelling workflow (`python -m app.evaluation prepare/html/score`) already
  exists; a person still has to label a sample. This cannot be done by the assistant.
- Usefulness of KEV/EPSS priority and of AI taint specs on real projects is not evaluated; no live
  provider call was made (all tests use fake transports).
- Secret verification has no AWS verifier (signing needs the secret key).
- On a live-audit retry the BOLA test accounts are gone (never stored); a resumed audit reuses a
  completed access-check stage, a fresh retry skips it unless credentials are supplied again.
