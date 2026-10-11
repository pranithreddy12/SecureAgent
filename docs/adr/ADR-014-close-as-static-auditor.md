# ADR-014: Close the project as a grey-box static security auditor

- **Date:** 2026-10-11
- **Status:** Accepted (decision by the project owner: "Go with option 1")
- **Supersedes (delivery scope only):** the live multi-agent pipeline as a *delivered* capability in the
  original brief. Its design (ADR-001, ADR-003, ADR-005, `docs/agent-workflow.md`) is retained.

## Context

`docs/PROJECT_CLOSEOUT.md` §6 offered two ways to close: (1) deliver SecureAgent as a grey-box static
auditor, which is complete, tested and demonstrable; or (2) finish the live multi-agent platform, which
depends on target management that the project cannot currently produce (the two owner-supplied files).

## Decision

Deliver **Option 1**. SecureAgent is closed as:

> A grey-box application-security auditor for developers' **own** code: deterministic static analysis
> (injection, access control, business logic, secrets, dependencies, misconfiguration), persisted web
> audits with reports, attack chains and verified fix patches, a CLI, CI gating and an MCP server.

Consequences for the repository:

- The live-target pipeline (targets, live authorization, reconnaissance, OWASP ZAP, Nuclei, safe
  validation, validator, LangGraph) is **out of the delivered scope**, not "in progress". Its requirement
  rows are marked *Deferred (ADR-014)*; designs and the hand-off spec stay in `docs/`.
- The product does not advertise unbuilt features: unbuilt navigation entries are removed from the UI and
  the unused ZAP service is moved behind a Compose profile (`--profile pipeline`).
- Acceptance criteria 5, 7, 10 and 14 (and the live forms of 8-9, 12) are **explicitly not met**; they
  are not reinterpreted. `SPECIFICATION.md` (baseline) is unchanged except for an appended scope note.
- Nothing is removed that a later Option 2 would need: target schemas, the `targets`/`authorization_records`
  tables, settings for ZAP/Nuclei and the designs remain.

## Alternatives

- **Option 2** (finish the platform) -- remains available later; requires the two target-management files.
- **Keep both claims** (static auditor *and* "pipeline coming") -- rejected: it blurs what is delivered.

## Consequences

- Marketing/README language and academic framing must describe a *static* auditor; "multi-agent
  orchestration" is described as designed future work.
- If Option 2 is resumed, reverse the "Deferred" markings and restore the navigation entries as pages exist.
