# Requirements Traceability

Source key: **SPEC** = `SPECIFICATION.md` (baseline, from owner brief — PPT not yet
provided), **BRIEF** = owner's implementation brief (2026-10-02).
Status: Planned → In Progress → Implemented → Tested.

| # | Requirement | Source | Implementation (planned path) | Status |
|---|---|---|---|---|
| R1 | User registration / login / me / logout | SPEC §3 | backend/app/api/auth.py, services/user_service.py, core/security.py | Implemented + Tested |
| R2 | Target CRUD | SPEC §3 | backend/app/api/targets.py | Blocked (see PROJECT_MEMORY §3) |
| R3 | Authorization confirmation + record | SPEC §13 | backend/app/services/authorization_service.py | Blocked (see PROJECT_MEMORY §3) |
| R4 | Target safety validation (scheme, private/loopback/link-local/metadata blocking, allowlist) | SPEC §13 | backend/app/security/target_validation.py | Blocked (see PROJECT_MEMORY §3) |
| R5 | Scope enforcement in every tool | SPEC §13 | backend/app/tools/* | Blocked (see PROJECT_MEMORY §3) |
| R6 | LangGraph audit workflow + AuditState | SPEC §7, ADR-001 | backend/app/workflows/audit_graph.py | Planned |
| R7 | Reconnaissance Agent | SPEC §8 | backend/app/agents/reconnaissance_agent.py, tools/recon_tool.py | Planned |
| R8 | Vulnerability Scanner Agent | SPEC §8 | backend/app/agents/vulnerability_scanner_agent.py | Planned |
| R9 | OWASP ZAP integration | SPEC §9 | backend/app/tools/zap_tool.py | Planned |
| R10 | Nuclei integration | SPEC §9 | backend/app/tools/nuclei_tool.py | Planned |
| R11 | Exploitation Agent → Safe Validation Agent | SPEC §8, ADR-003 | backend/app/agents/safe_validation_agent.py, tools/validation_tool.py | Planned |
| R12 | Validator Agent / false-positive reduction | SPEC §8 | backend/app/agents/validator_agent.py | Planned |
| R13 | OWASP / CWE / CVE / CVSS mapping (no fabrication) | SPEC §12 | per-detector metadata in backend/app/analysis/*.py; CVE via OSV; reports/report.html | Implemented + Tested for static findings (CVE only from real advisories; CVSS never populated for OSV findings; no central standards.py) |
| R14 | Report Agent — HTML + PDF | SPEC §8, §15 | backend/app/reports/ (renderer, template), schemas/report.py, api/audits.py (download); agent pending | In Progress (rendering, persistence and download done for source audits; Report *agent* needs the live pipeline) |
| R15 | Audit progress tracking + logs | SPEC §3 | services/audit_service.py, api/audits.py, frontend/app/(app)/audits/[id] | Implemented + Tested for source audits (ADR-011); live-audit stages pending |
| R16 | Background execution | BRIEF §43, ADR-005 | services/audit_service.py, api/audits.py (asyncio task per audit, startup sweep) | Implemented for source audits (single replica; no resume) |
| R17 | Resumable / idempotent audits | BRIEF §34 | runner + fingerprint constraint | Planned |
| R18 | PostgreSQL schema + migrations | SPEC §9, ADR-002 | backend/app/models/, backend/alembic/ | Implemented + Tested |
| R19 | Dashboard + charts | SPEC §15 | frontend/app/(app)/dashboard | In Progress (shell + live health + honest empty state; no data/charts until audits exist) |
| R20 | Targets / audits / findings / reports / activity / settings UI | SPEC §15 | frontend/app/* | In Progress (login, register, dashboard with real data, settings, audits list + detail with findings/chains/logs/report done; targets and global findings/activity pages need target management) |
| R21 | Demo mode, clearly labelled | SPEC §15, ADR-004 | backend/app/demo/, cli `demo`, docs/demo-guide.md | In Progress (static-engine demo implemented + tested; fixture demo of the live agent pipeline pending targets) |
| R22 | Local vulnerable lab target (Juice Shop) | BRIEF §31 | docker-compose `lab` profile | In Progress (service defined) |
| R23 | Docker Compose deployment | SPEC §15 | docker-compose.yml, docker/ (backend image pinned to requirements.lock) | In Progress (stack builds, runs and is Playwright-tested in CI; `./workspace` mounted for source audits; ZAP/Nuclei unused; Nuclei binary not in image) |
| R24 | Automated tests incl. security restrictions | SPEC §15 | backend/tests/ (346 tests, 93% coverage), frontend Vitest (24), Playwright (6) | In Progress (auth, throttling, ownership, path confinement, redaction, escaping, suppression, report CSP tested; **target safety restrictions untestable until built**) |
| R25 | Optional LLM reasoning with deterministic fallback | SPEC §6 | backend/app/agents/llm.py | Planned |
| R26 | Structured logging per audit ID | BRIEF §33 | backend/app/core/logging.py | Planned |
| R27 | UML diagrams (7) matching the code | SPEC §16 | docs/diagrams/ | Implemented (validated) |
| R28 | Academic docs | SPEC §15 | docs/*.md, README, docs/PROJECT_CLOSEOUT.md | Implemented for what exists (architecture, agent-workflow, security-model, database, api, static-analysis, testing, deployment, demo-guide) |
| R30 | Source repository ingestion (authorized, read-only, limits) | ADR-008 | backend/app/analysis/ingest.py | Implemented + Tested |
| R31 | Code Intelligence: routes + authz (FastAPI/Flask/Express/Django/NestJS) | ADR-008 | backend/app/analysis/routes.py | Implemented + Tested; models/trust-boundaries pending |
| R32 | Business-logic flaw detection (BOLA/IDOR, authz, workflow, client-trust, limits, state) | ADR-008 | routes.py (function-level authz done); rest planned | In Progress |
| R33 | Hardcoded-secret detection (redacted) | ADR-008 | backend/app/analysis/secrets.py + app/cli.py | Implemented + Tested |
| R41 | SARIF 2.1.0 output for GitHub code scanning | project (integration) | backend/app/analysis/sarif.py | Implemented + Tested |
| R42 | Logging & monitoring checks (A09: sensitive data in logs, swallowed exceptions) | OWASP A09 | backend/app/analysis/logging_checks.py | Implemented + Tested |
| R40 | CI adoption: baseline, --fail-on, installable `secureagent` CLI, GitHub Action | project (usability) | backend/app/analysis/baseline.py, app/cli.py, pyproject.toml, docs/ci/ | Implemented + Tested |
| R39 | Security-misconfiguration detection (debug, CORS, JWT, CSRF, autoescape, hosts, cookies) | ADR-008 (OWASP A05) | backend/app/analysis/misconfig.py | Implemented + Tested |
| R38 | IDOR / object-level authorization analysis | ADR-008 (OWASP A01, CWE-639) | backend/app/analysis/access_control.py | Implemented + Tested |
| R37 | Taint: injection/SSRF/path/open-redirect (interprocedural Python + JS) | ADR-008 (OWASP A03/A10/A01) | backend/app/analysis/taint.py | Implemented + Tested |
| R36 | Dangerous-sink detection (deserialization, cmd/code exec, weak crypto, TLS, XXE, XSS sink) | ADR-008 (OWASP A02/A03/A05/A08) | backend/app/analysis/sinks.py | Implemented + Tested |
| R35 | Dependency / known-vulnerability scanning (OSV) | ADR-008 (extends R13 CVE) | backend/app/analysis/dependencies.py, osv.py | Implemented + Tested |
| R34 | Developer-intent description (roles, workflows, test accounts) | ADR-008 | JSON rules via `--intent` / `secureagent-intent.json` (intent.py); UI planned | Partially Implemented (rules only; no roles/workflows/test-accounts yet) |
| R43 | Suppression controls: --exclude, .secureagentignore, inline ignore (always counted) | project (real-world usability) | backend/app/analysis/ingest.py, scanner.py, cli.py | Implemented + Tested |
| R44 | Report polish: risk rating, Fix-first priorities, grouped remediation, ToC | project (report quality) | backend/app/schemas/report.py, reports/templates/report.html | Implemented + Tested |
| R45 | Dependency-light installable scanner (no web stack required) | ADR-009 | backend/app/core/enums.py, pyproject.toml, tests/test_cli_standalone.py | Implemented + Tested |
| R46 | Reproducible backend build (pinned lock) | project (supply chain) | backend/requirements.lock, docker/backend.Dockerfile | Implemented |
| R47 | Repo CI workflow (backend, frontend, self-scan, e2e) | project | .github/workflows/ci.yml | Implemented; four jobs green at close-out (first run found two real failures, fixed) |
| R48 | Business-logic detectors (mass assignment, client-trusted privilege/value) and developer intent spec | ADR-008, ADR-010 (OWASP A01/A04) | backend/app/analysis/business_logic.py, intent.py, tests/test_business_logic.py | Implemented + Tested (Python only; workflow-order not built) |
| R49 | Authorization matrix + inconsistent-authorization outliers | ADR-010 (OWASP A01) | backend/app/analysis/authz_matrix.py, tests/test_authz_matrix.py | Implemented + Tested (heuristic; Python and JS route extractors) |
| R50 | Detector accuracy benchmark (labelled corpus, precision/recall, CI floor) | project (trust) | backend/app/analysis/benchmark.py, backend/benchmark/corpus/, tests/test_benchmark.py, docs/benchmark.md | Implemented + Tested (bundled corpus is author-written: regression guard, not a real-world detection rate) |
| R51 | MCP server exposing the scanner to AI assistants (scan_snippet, scan_path, authorization_matrix) | project (integration) | backend/app/mcp_server.py, tests/test_mcp_server.py, docs/mcp.md | Implemented + Tested (stdio transport only; stdlib JSON-RPC) |
| R52 | Persisted source audits: API, runner, progress, logs, history, report download (no live target) | ADR-011 (SPEC criteria 8, 9, 21-23) | backend/app/api/audits.py, services/audit_service.py, models/audit.py, alembic b7c1d2e3f4a5, tests/test_audits.py | Implemented + Tested (inline-run tests; no crash-recovery sweep yet) |
| R53 | Attack chains: findings combined into narratives with fix-first and assumptions | ADR-012 | backend/app/analysis/chains.py, schemas/report.py, report template (section 8), UI audit page, tests/test_chains.py | Implemented + Tested (structural rules; Python/JS routes; never escalates severity) |
| R54 | Workflow-order detector (terminal state set without a state precondition) | ADR-008/010 (OWASP A04, CWE-841) | backend/app/analysis/workflow.py, tests/test_workflow.py | Implemented + Tested (Python only; model-layer state machines are invisible) |
| R55 | Frontend component/unit tests (Vitest + Testing Library) | SPEC §15 (testing) | frontend/**/*.test.ts(x), vitest.config.mts, CI step | Implemented (24 tests; no browser e2e) |
| R56 | Admin bootstrap command (password via env/prompt, never argv) | SPEC §10 (security model) | backend/app/manage.py, tests/test_manage.py | Implemented + Tested |
| R57 | Verified fix patches (`secureagent fix`, MCP `suggest_fixes`) | ADR-013 | backend/app/analysis/fixes.py, tests/test_fixes.py | Implemented + Tested (7 finding types; single-file verification; behaviour not proven preserved) |
| R58 | Browser end-to-end tests (Playwright) of the audit journey | SPEC §15 (testing), criteria 1-4, 8-9, 21-23 | frontend/e2e/, playwright.config.ts, CI job `e2e` | Implemented (6 tests; Chromium only) |
| R29 | Continuous / scheduled testing | SPEC §14 | — (architecture extensible only) | Deferred |
