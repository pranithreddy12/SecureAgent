# ADR-008: Grey-box business-logic analysis (source code + developer intent + dynamic recon)

- **Date:** 2026-10-03
- **Status:** Accepted
- **Supersedes:** nothing. **Extends** the original black-box scope (see
  `PROJECT_MEMORY.md` §15 Scope Change 2026-10-03b).

## Context

The original specification positioned SecureAgent as a black-box (DAST) auditor:
it discovers a live application's surface and runs ZAP/Nuclei against it. That
finds pattern-based issues well (missing headers, injection signatures, known
CVEs) but is effectively blind to **business-logic vulnerabilities** — flaws that
depend on what the application is *meant* to do: broken access control between
users, workflow steps performed out of order, server trust of client-supplied
values, missing limits, inconsistent authorization across endpoints.

The project owner's goal is explicitly to help the developers of an application
find and fix these complex logic flaws before attackers exploit them. A scanner
cannot infer intended rules from traffic alone. The two reliable sources of
"intended behaviour" are:

1. the application's **own source code** (ground truth of what is implemented), and
2. a short **developer description** of roles and sensitive workflows.

## Decision

SecureAgent becomes a **grey-box** auditor. In addition to dynamic recon, it
ingests the application's **source repository** (which the user confirms they own
or are authorized to analyse) and an optional developer description, and builds a
structured **Application Model** that the business-logic reasoning stage uses.

Pipeline position (full graph in `docs/business-logic-engine.md`):

```
Authorization → Target & Source Validation
      ├─ Dynamic Reconnaissance (existing)
      └─ Code Intelligence (new, static)
                    ↓
          Application Model (merged)
                    ↓
  Vulnerability Scanning (ZAP/Nuclei)   Business-Logic Reasoning (new)
                    ↓                              ↓
                 Safe Validation (non-destructive, existing)
                    ↓
                 Validator → Report
```

Principles that keep this safe and in-scope:

- **Static-first.** The Code Intelligence agent *parses* code (AST / tree-sitter)
  to extract facts deterministically; the LLM reasons on top of those facts but
  never has its output treated as ground truth for routing or severity.
- **Never execute the repo.** The analyser reads files only. It does not run
  build scripts, tests, or any code from the uploaded project. Dependencies and
  vendored code are ignored, not installed.
- **Authorization covers the code too.** The same authorization gate applies: the
  user confirms they are authorized for both the target URL and the source.
- **Secrets are findings, not loot.** Hardcoded credentials/keys discovered in
  code are reported (redacted) as findings; their values are never stored in full,
  logged, or sent anywhere.
- **Confirmation stays non-destructive.** Logic-flaw candidates are confirmed by
  the existing Safe Validation agent, which gathers observational evidence only
  (see ADR-003) against the authorized target.
- **Honest classification.** Many logic flaws cannot be safely proven end-to-end;
  the validator marks these `likely`/`suspicious` with the code evidence that
  motivated them, and the report explains the limitation.

## Alternatives

- **Stay black-box** — simpler, but cannot meaningfully find logic flaws; fails
  the owner's primary goal.
- **Pure-LLM "read the repo and find bugs"** — no deterministic model, high false
  positives, not reproducible, not defensible for an academic evaluation.
- **Full taint/dataflow SAST engine (e.g. CodeQL-class)** — powerful but a project
  in itself; we take a lighter structural-model approach and leave deep dataflow as
  future work.

## Consequences

- New agents (Code Intelligence, Business-Logic Reasoning), a new Application Model
  artifact, a repo-ingestion tool with strict limits, and schema additions
  (design in `docs/business-logic-engine.md` and `docs/database.md`).
- New dependencies expected: a multi-language parser (tree-sitter) and git/zip
  ingestion. Language coverage starts with the most common web stacks and is
  extensible.
- The product is now grey-box; marketing/academic framing updates accordingly.
  Black-box-only audits remain supported (source is optional but recommended).
