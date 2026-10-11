# ADR-018: Opt-in AI validator and report-narrative stages in the pipeline

- **Date:** 2026-10-12
- **Status:** Accepted
- **Relates to:** ADR-016 (pipeline), ADR-017 (LLM review), ADR-014 (scope)

## Context

The pipeline's "agents" were deterministic stages. The two places where a language model adds
something the rules cannot are *judging* whether a finding is real (the validator's job) and *writing*
the executive summary. Both must stay advisory: the deterministic result has to be reproducible and is
what gates a build.

## Decision

Two optional stages are added to the LangGraph workflow, both **opt-in per audit**:

```
... validator -> ai_validator -> correlation -> ai_narrative -> report
```

| Stage | Input | Output | Authority |
|---|---|---|---|
| `ai_validator` | The 15 most severe reviewable findings: enclosing function + <= 3 helpers + taint path (secrets redacted; never secret findings or git-ignored files) | `validation_result.ai_review` on each finding (verdict, confidence, reason, **verified** quote) | Shown beside the finding. **Never** changes status, severity, fingerprint or the gate. |
| `ai_narrative` | A **code-free** fact sheet: project name, overall risk, counts, top finding titles/types/locations, chain titles, route counts, technologies, limitations | `stage_state.ai.narrative` -> the report's executive summary, labelled "Written by AI (model) from the structured findings only; the findings below are authoritative" | Text only. Rejected (deterministic summary used) if it is empty, too long, contains JSON/code fences or makes exploitation/confirmation claims. |

Consent and configuration:
- The request must carry `ai_review: true` (UI: an unticked checkbox, shown only when the server has
  `LLM_API_KEY`); without a server key the API answers 400 and creates nothing.
- The consent and timestamp are stored on the audit and logged (`ai_consent`).
- The operator configures `LLM_API_KEY` / `LLM_MODEL`; users never supply keys through the web app.

Failure model (**advisory stages degrade, they never fail the audit**):
- API/network/key problems, unusable answers and unexpected errors are recorded
  (`ai.problems`, a `degraded` log line) and the audit completes with its deterministic result.
- `StageSpec.advisory = True` makes the graph roll back that stage's partial writes and continue.

## Not claimed

- The stages are **not evaluated**: their precision gain and hallucination rate are unmeasured
  (research question RQ5). A live provider call has not been exercised by the project (fake transport).
- They do not make the scanner or the authorization gate "AI": those stay deterministic on purpose.
- They are opt-in per audit; the default pipeline is unchanged and sends nothing.

## Alternatives

- **LLM sets the final status** -- rejected: non-deterministic and steerable by text in the code.
- **Send whole files for the narrative** -- rejected: the summary needs facts, not source.
- **User-supplied keys per audit** -- rejected for the web app: keys in a multi-user store are a
  liability; the CLI (`review`) already covers bring-your-own-key.

## Consequences

- The report timeline lists the AI stages with notes like "skipped: AI review was not requested".
- Resume works unchanged: skipped/degraded AI stages are marked completed with their note.
