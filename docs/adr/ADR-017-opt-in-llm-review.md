# ADR-017: Opt-in LLM review of findings

- **Date:** 2026-10-12
- **Status:** Accepted
- **Relates to:** ADR-008 (static-first), ADR-013/015 (verification and validation rules), ADR-014 (scope)

## Context

A real-project scan showed the deterministic engine produces many false positives that a model (or a
human) clears quickly by reading a few functions. A language model is good at exactly that judgement,
but it is non-deterministic, can hallucinate, costs money and -- critically -- needs source code to
leave the machine.

## Decision

Add `secureagent review` as a **separate, opt-in second-opinion layer**, with these properties:

| Concern | Decision |
|---|---|
| **Consent** | Nothing is sent without `--yes` or an interactive "y". A summary states the number of findings, size, files and model first. `--dry-run` prints the exact prompts. A non-interactive session without `--yes` refuses. |
| **Key** | `ANTHROPIC_API_KEY` only (never an argument, never logged, never stored). No key means no network call. |
| **What is sent** | For each finding: the enclosing function, up to 3 helpers it calls (same file or sibling modules, <= 40 lines each), the detector's explanation and taint path -- capped at ~9 KiB. |
| **Secrets** | Provider-key shapes and secret-named assignments are replaced with `[REDACTED]`; hardcoded-secret and dependency findings are never reviewed; git-ignored files are never sent. |
| **Prompt injection** | The system prompt marks the code as untrusted data. The model's answer is parsed as strict JSON; only the transport's JSON can set a verdict. |
| **Evidence check** | The model must quote one line that supports its verdict. If that quote is not literally in the code that was sent, the verdict is downgraded to `unclear` and the note says so. |
| **Authority** | The verdict never changes a finding's status, severity, baseline fingerprint or the CI gate. It is displayed beside the finding as an "unverified second opinion". For high-confidence false positives the CLI prints the `suppress` command, leaving the decision to a human. |
| **Cost control** | `--limit` (default 15), `temperature: 0`, a local cache keyed by (model, prompt) so reruns are free. |
| **Dependencies** | Standard-library HTTP; no SDK. The CLI stays dependency-light (ADR-009). |

## Not delivered / not claimed

- **No evaluation yet.** Whether LLM review improves precision, and how often it errs, is unmeasured
  (research question RQ5 in `docs/paper/PAPER_PLAN.md`). Until measured, treat verdicts as hints.
- **Not in the web app or MCP.** Claude Code over MCP is already an LLM reviewer; the web pipeline
  stays deterministic.
- **No agentic exploration.** The model sees a fixed excerpt; it cannot read other files or run code.
- **A live call was not exercised** in the project's tests (a fake transport is used); the first real
  run is the user's.

## Alternatives

- **Send whole files / the whole repository** -- more context, much more exposure and cost.
- **Let the LLM set status or gate builds** -- rejected: non-deterministic and can be manipulated by
  text inside the code.
- **Local model** -- attractive for privacy; the `Transport` seam allows it later.

## Consequences

- Third-party data processing is opt-in and visible; users who cannot send code never see it used.
- The `ai_review` field on a finding is additive and optional in reports.
