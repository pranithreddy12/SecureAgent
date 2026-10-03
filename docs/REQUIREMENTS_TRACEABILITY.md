# Requirements Traceability

Source key: **SPEC** = `SPECIFICATION.md` (baseline, from owner brief — PPT not yet
provided), **BRIEF** = owner's implementation brief (2026-10-02).
Status: Planned → In Progress → Implemented → Tested.

| # | Requirement | Source | Implementation (planned path) | Status |
|---|---|---|---|---|
| R1 | User registration / login / me / logout | SPEC §3 | backend/app/api/auth.py, services/auth_service.py | Planned |
| R2 | Target CRUD | SPEC §3 | backend/app/api/targets.py | Planned |
| R3 | Authorization confirmation + record | SPEC §13 | backend/app/services/authorization_service.py | Planned |
| R4 | Target safety validation (scheme, private/loopback/link-local/metadata blocking, allowlist) | SPEC §13 | backend/app/security/target_validation.py | Planned |
| R5 | Scope enforcement in every tool | SPEC §13 | backend/app/tools/* | Planned |
| R6 | LangGraph audit workflow + AuditState | SPEC §7, ADR-001 | backend/app/workflows/audit_graph.py | Planned |
| R7 | Reconnaissance Agent | SPEC §8 | backend/app/agents/reconnaissance_agent.py, tools/recon_tool.py | Planned |
| R8 | Vulnerability Scanner Agent | SPEC §8 | backend/app/agents/vulnerability_scanner_agent.py | Planned |
| R9 | OWASP ZAP integration | SPEC §9 | backend/app/tools/zap_tool.py | Planned |
| R10 | Nuclei integration | SPEC §9 | backend/app/tools/nuclei_tool.py | Planned |
| R11 | Exploitation Agent → Safe Validation Agent | SPEC §8, ADR-003 | backend/app/agents/safe_validation_agent.py, tools/validation_tool.py | Planned |
| R12 | Validator Agent / false-positive reduction | SPEC §8 | backend/app/agents/validator_agent.py | Planned |
| R13 | OWASP / CWE / CVE / CVSS mapping (no fabrication) | SPEC §12 | backend/app/security/standards.py | Planned |
| R14 | Report Agent — HTML + PDF | SPEC §8, §15 | backend/app/agents/report_agent.py, reports/ | Planned |
| R15 | Audit progress tracking + logs | SPEC §3 | services/audit_runner.py, api/audits.py | Planned |
| R16 | Background execution | BRIEF §43, ADR-005 | backend/app/workflows/runner.py | Planned |
| R17 | Resumable / idempotent audits | BRIEF §34 | runner + fingerprint constraint | Planned |
| R18 | PostgreSQL schema + migrations | SPEC §9, ADR-002 | backend/app/models/, backend/alembic/ | Planned |
| R19 | Dashboard + charts | SPEC §15 | frontend/app/dashboard | Planned |
| R20 | Targets / audits / findings / reports / activity / settings UI | SPEC §15 | frontend/app/* | Planned |
| R21 | Demo mode, clearly labelled | SPEC §15, ADR-004 | backend/app/demo/ | Planned |
| R22 | Local vulnerable lab target (Juice Shop) | BRIEF §31 | docker-compose `lab` profile | In Progress (service defined) |
| R23 | Docker Compose deployment | SPEC §15 | docker-compose.yml, docker/ | In Progress (files written, images not yet built) |
| R24 | Automated tests incl. security restrictions | SPEC §15 | backend/tests/ | Planned |
| R25 | Optional LLM reasoning with deterministic fallback | SPEC §6 | backend/app/agents/llm.py | Planned |
| R26 | Structured logging per audit ID | BRIEF §33 | backend/app/core/logging.py | Planned |
| R27 | UML diagrams (7) matching the code | SPEC §16 | docs/diagrams/ | Planned |
| R28 | Academic docs | SPEC §15 | docs/*.md | In Progress (design docs done) |
| R29 | Continuous / scheduled testing | SPEC §14 | — (architecture extensible only) | Deferred |
