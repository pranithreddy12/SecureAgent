# ADR-003: "Exploitation Agent" implemented as a Safe Validation Agent

- **Date:** 2026-10-02
- **Status:** Accepted

## Context
The PPT architecture includes an Exploitation Agent. The project must remain a tool
for authorized, non-destructive testing.

## Decision
Implement that stage as `SafeValidationAgent`: deterministic, per-category
validators that gather non-destructive evidence (inert unique markers, re-fetching
headers/paths, comparing recorded responses). No data extraction, no state changes
beyond a single benign marker submission, no bypass of controls. All requests go
through `validation_tool`, which enforces authorization, scope, rate and timeouts.
Findings without a safe strategy are left unvalidated and labelled as such.

Documentation and UML label it: "SafeValidationAgent (controlled implementation of
the PPT's Exploitation Agent)".

## Alternatives
- Full exploitation frameworks — rejected: destructive and out of scope.
- No validation stage — rejected: false-positive reduction is a core objective.

## Consequences
- Some true vulnerabilities will remain `likely`/`suspicious` rather than `confirmed`;
  the report's Limitations section states this.
