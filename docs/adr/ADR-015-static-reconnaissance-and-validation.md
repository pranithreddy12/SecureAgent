# ADR-015: Static reconnaissance and rule-based finding validation (not their live counterparts)

- **Date:** 2026-10-11
- **Status:** Accepted
- **Relates to:** ADR-003 (safe validation), ADR-008 (grey-box), ADR-014 (delivered scope)

## Context

The original brief lists "run reconnaissance" (criterion 10) and "safely validate findings"
(criterion 14). Both mean *interacting with a running target*. That needs, first, the target
authorization and network-safety gate (what may be contacted, from where, at what rate) -- the part
of the project that was never built (ADR-014). Probing without that gate would break the project's own
safety rules (ADR-003), so neither live capability is implemented.

## Decision

Deliver the closest honest, in-scope equivalents and **name them as what they are**:

| Delivered | What it does | What it is *not* |
|---|---|---|
| **Source reconnaissance** (`app/analysis/recon.py`) -- "application model" | From source files: technologies, inputs read (query/body/path/header/cookie names), outbound hosts referenced, environment variables, interesting (privileged) routes. Shown in the report (sections 6-7), CLI `--recon`, JSON, MCP `application_model`, and the audit page. | Not a crawl, port scan or fingerprint of a live system. Nothing is contacted. |
| **Rule-based validation** (`app/analysis/validation.py`) | Reclassifies findings whose *location* shows no production risk: test/fixture/example/sample/mock code and `*.example`-style files; debug flags in development-only config. Status becomes `informational`, confidence halves, the reason names the rule. | Not proof of exploitability; never promotes to `confirmed`; never deletes. |

Consequences wired through the product:
- Reclassified findings do **not** drive the overall risk rating, do not form attack chains, and do not
  fail `--fail-on` gates; they remain visible with their evidence.
- The report states how many findings were reclassified and by which rule.

## Not delivered (explicit)

- **Live reconnaissance** (crawling, header/technology fingerprinting, endpoint discovery) -- criterion 10
  stays unmet.
- **Safe validation** (non-destructive confirmation against a running target) -- criterion 14 stays unmet.
  The existing *fix verification* (ADR-013) is unrelated: it verifies patches, not exploitability.

## Alternatives

- **Label these as criteria 10/14 "done"** -- rejected: it would misstate what the system can do.
- **Corroboration rules ("two detectors agree => likely")** -- rejected after review: the detectors
  share inputs (intent violations derive from IDOR findings, for example), so agreement would not be
  independent evidence.

## Consequences

- If the live pipeline is resumed (Option 2), the application model becomes the seed for target
  scope/discovery and these static rules remain as a pre-filter.
