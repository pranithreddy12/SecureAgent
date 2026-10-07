# SecureAgent – UML & Architecture Diagrams

These diagrams describe the **actual implementation** as of 2026-10-08. Where the
academic architecture (the multi-agent audit pipeline) is **designed but not yet
implemented**, it is drawn separately and labelled as such — nothing here depicts
functionality that does not exist in the code.

All diagrams are Mermaid (render on GitHub and in most Markdown viewers).

| # | Diagram | Scope | File |
|---|---------|-------|------|
| 1 | Use Case | Actors and what they can actually do today | [01-use-case.md](01-use-case.md) |
| 2 | Class | Static-analysis domain classes + ORM models | [02-class.md](02-class.md) |
| 3 | Activity | The `secureagent scan` pipeline | [03-activity.md](03-activity.md) |
| 4 | Sequence | Scan CLI flow, and the auth login flow | [04-sequence.md](04-sequence.md) |
| 5 | System Architecture | Implemented components + planned pipeline | [05-system-architecture.md](05-system-architecture.md) |
| 6 | Multi-Agent Workflow | **Designed** LangGraph pipeline (not implemented) | [06-agent-workflow.md](06-agent-workflow.md) |
| 7 | Database ER | The 8 implemented tables | [07-database-er.md](07-database-er.md) |

## Implementation status at a glance

- **Implemented & tested:** static analysis engine (ingestion, secrets, dependencies
  + OSV, dangerous sinks, interprocedural + JS taint, IDOR, misconfiguration),
  reporting (HTML/PDF/JSON/SARIF), baseline + CI gating, the `secureagent` CLI;
  authentication (register/login/logout/me); the PostgreSQL schema; the frontend auth
  pages + dashboard shell.
- **Designed, not implemented (blocked on target management):** the multi-agent audit
  pipeline (Reconnaissance, Vulnerability Scanner, Safe Validation [the controlled
  implementation of the PPT "Exploitation Agent"], Validator, Report agents) and the
  LangGraph orchestration, including OWASP ZAP and Nuclei integration. See diagram 6
  and `docs/agent-workflow.md`.
