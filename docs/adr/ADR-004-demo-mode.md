# ADR-004: Fixture-backed Demo Mode

- **Date:** 2026-10-02
- **Status:** Accepted

## Context
The academic demonstration must work without an LLM key, ZAP or Nuclei, but
simulated output must never be presented as real.

## Decision
Demo mode swaps only the **tool adapters** (recon, ZAP, Nuclei, validation HTTP) for
fixture readers (`backend/app/demo/fixtures/*.json`). The real graph, validator,
persistence and report generation run on that data. Demo audits are flagged
`is_demo=true` and labelled "DEMO / SIMULATED SECURITY AUDIT" in the UI, API and
every report page. No network traffic is sent in demo mode.

Global `DEMO_MODE=true` forces all audits to demo; otherwise a user may choose a demo
audit explicitly.

For genuine testing, a `lab` Docker Compose profile runs OWASP Juice Shop with
`ALLOW_PRIVATE_TARGETS=true` and an allowlist.

## Alternatives
- Mock HTTP API responses — rejected: would bypass the real pipeline.

## Consequences
- Demo exercises real code paths, which also makes it a useful integration test.
