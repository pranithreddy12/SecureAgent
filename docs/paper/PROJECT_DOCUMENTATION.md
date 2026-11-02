# SecureAgent: Project Documentation for Publication

Status: compiled 2026-11-01, updated 2026-11-02 from the repository (`PROJECT_MEMORY.md`, `docs/`, ADR-001..045,
source tree).
Every number below is copied from a project document or an ADR; none was re-measured when this file was
written. Figures marked *(author corpus)* or *(tuned-on)* are **not** independent and must not be quoted as
real-world accuracy. See section 9 and `docs/paper/PAPER_PLAN.md` for what a submission still needs.

---

## 1. Abstract (draft)

SecureAgent is a multi-agent application-security auditor. Its main mode is a **grey-box static analyser**
that reads a developer's source code without executing it, detects injection, access-control, secret,
dependency, infrastructure and business-logic flaws, links them into attack chains, proposes
machine-verified fixes, and reports under an explicit **honesty model**: static analysis alone never
labels a finding "confirmed", CVE/CVSS data come only from real advisories, and any AI component is
opt-in, redacted and advisory. A second mode audits **authorized live targets** with OWASP ZAP and Nuclei
behind SSRF-hardened target validation. The tool is delivered as a CLI, a CI gate / GitHub Action, an MCP
server for AI coding assistants, a VS Code extension, and a web application (FastAPI + Next.js +
PostgreSQL). The evaluation is deliberately candid: the author-written benchmark scores 97 % precision /
95 % recall *(author corpus)*, but on real projects the first precision measurement was 28 %, and across
eleven untouched vulnerable applications pooled recall of planted flaws is 55 % (199/361).

## 2. Problem and motivation

- Scanners find known patterns but cannot infer *intended* rules, so business-logic flaws (BOLA/IDOR,
  inconsistent authorization, client-trusted prices or roles, workflow bypass) are missed.
- SAST output is noisy; developers lose trust. Tools rarely say how sure they are or why.
- LLM reviewers reason well but are non-exhaustive and can hallucinate evidence.
- Authors of security tools usually benchmark on corpora they wrote, which overstates accuracy.

**Design response:** a deterministic scanner as the exhaustive layer, a developer *intent spec* for rules a
machine cannot guess, a status model that never over-claims, and optional LLM review that is verified against
the code and has no authority over results.

## 3. Contributions

1. **Grey-box static auditor** combining taint analysis (within function, file, across files, via return
   values), route/authorization extraction for six frameworks, an authorization matrix, business-logic
   detectors, and a JSON developer-intent spec (ADR-008, 010).
2. **Honesty model**: statuses `likely / suspicious / informational / false_positive`; static findings are
   never `confirmed`; CVE only from advisories; CVSS v3 computed only from a published vector.
3. **Verified fix patches**: a patch is "verified" only if it parses and a re-scan shows the finding gone
   with nothing new (ADR-013).
4. **Attack-chain correlation** as an interpretation layer: chain severity equals the worst member, never
   escalated (ADR-012).
5. **Opt-in, evidence-verified LLM layer** (review, validator, narrative) that cannot change status,
   severity or the CI gate (ADR-017, 018, 033).
6. **Multi-surface delivery**: CLI, SARIF/CI gating, GitHub Action, SBOM, MCP server, VS Code extension, web
   app, Electron shell (ADR-009, 038, 043).
7. **Candid evaluation methodology**: author benchmark vs. real-project precision vs. eleven untouched
   vulnerable-application sets with frozen truth lists, including retracted claims (ADR-021..041).
8. **Live-target pipeline** with SSRF-hardened target validation, authorization gates at three layers, and
   non-destructive evidence collection (ADR-003, 044).
9. **Context-aware hardening recommendations** (ADR-045): a deterministic interpretation layer that is not
   a finding, combining code signals with a developer-declared profile, citing evidence and stating what
   static analysis cannot verify. Evaluation status: **not evaluated**.

## 4. System overview

```
 Browser / Electron shell
        |  same-origin /api/*  (Next.js rewrite)
 +------v-------------------------------------------+
 | FastAPI backend   api -> services -> models      |
 |   asyncio audit runner (ADR-005)                 |
 |   LangGraph pipelines (source | live)            |
 |        agents -> tools (policy-enforcing)        |
 +--+------------+--------------+-------------------+
    |            |              |
 PostgreSQL 16   ZAP daemon     Nuclei (argv subprocess)
 (SQLAlchemy 2   (profile       -> AUTHORIZED TARGET only
  async+Alembic)  "pipeline")
 Optional LLM provider (Anthropic / Mistral), advisory only

 Stand-alone entry points that skip the web stack entirely:
   secureagent (CLI)  secureagent-mcp (MCP stdio)  action.yml  vscode-extension/
```

The scanner core (`backend/app/analysis/`) depends only on `jinja2` and `pydantic` (ADR-009). This is
enforced by `tests/test_cli_standalone.py`, which runs the CLI with SQLAlchemy and FastAPI imports poisoned.

## 5. Technology stack (what is used and why)

| Layer | Technology | Role / reason |
|---|---|---|
| Language | Python >= 3.12 (containers pin 3.12) | scanner, API, agents; `ast` module drives Python analysis |
| Scanner deps | `jinja2`, `pydantic` | only runtime deps of the CLI; optional `weasyprint` for PDF |
| API | FastAPI, Uvicorn, pydantic-settings | thin routers; Pydantic request/response contracts |
| Persistence | PostgreSQL 16, SQLAlchemy 2 (async), asyncpg, Alembic | ADR-002; enums as varchar + CHECK; UUID PKs; JSONB for semi-structured data |
| Auth | Argon2id (`argon2-cffi`), PyJWT HS256 in httpOnly SameSite=Lax cookie | ADR-006; login throttling; admin bootstrap |
| Orchestration | LangGraph (`StateGraph`) | ADR-001: LLM never routes; deterministic gates and edges |
| Reports | Pydantic context -> Jinja2 HTML -> WeasyPrint PDF | ADR-007; 19-section report |
| Live scanning | OWASP ZAP (REST), Nuclei (argv, `shell=False`) | only against authorized, validated targets |
| Supply chain | OSV API, CycloneDX 1.5 | CVE only from real advisories; SBOM export |
| LLM (optional) | Anthropic, Mistral via a provider table | ADR-017/033; consent, redaction, quote verification |
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind 4, `jszip` | client-side zip for folder picker; polling every 2 s |
| Testing | pytest, Vitest 5, Playwright | 661 backend tests passing (2026-11-02), 43 Vitest, 7 e2e |
| Packaging / CI | Docker Compose, GitHub Actions (4 jobs), composite Action, Electron | backend, frontend, self-scan, e2e |
| Integrations | MCP (hand-written stdio server), SARIF 2.1.0, VS Code extension (plain JS) | assistants, GitHub Security tab, editor |

## 6. How it works

### 6.1 Static analysis pipeline (`backend/app/analysis/`)

1. **Ingestion** (`ingest.py`): read-only, size/count limits, `--exclude`, `.secureagentignore`, gitignore
   awareness; code is never executed.
2. **Detectors** (see 6.2) produce findings with a type, location, confidence, status and, for injection, a
   numbered **taint path**.
3. **Interpretation layers**: validation rules (`validation.py`: test/example/dev-only code and git-ignored
   files -> `informational`, reason recorded), suppressions (justified, expiring, count-capped), baseline
   fingerprints (line-independent), attack chains (`chains.py`), authorization matrix (`authz_matrix.py`),
   static reconnaissance / application model (`recon.py`).
4. **Outputs**: text, JSON, SARIF 2.1.0, HTML, PDF, CycloneDX SBOM; `--fail-on` gating; `--since REF` diff
   mode (`gitdiff.py`).
5. **Fixes** (`fixes.py`): deterministic patches for seven finding types (weak hash, TLS/JWT verification
   off, unsafe `yaml.load`, debug/CSRF flags, hardcoded Python secrets), applied only if verified.

### 6.2 Detector families

| Family | Mechanism | Main limit |
|---|---|---|
| Secrets (`secrets.py`) | provider-key patterns + word-matched secret names, entropy; always redacted | placeholders and git-ignored files demoted |
| Dependencies (`dependencies.py`, `osv.py`, `cvss.py`) | lockfile parse (requirements, Pipfile.lock, poetry.lock, package-lock.json) + OSV; CVSS v3 from vector | pinned versions only; needs network |
| Injection (`taint.py`, `sinks.py`) | AST taint for Python, cross-file/return-value; sanitizer and allow-list modelling; regex for JS/TS; structural SQL rule | JS is regex-based; some classes are provenance-agnostic |
| Dangerous code (`extra_detectors.py`) | deserialization, `shell=True`, `eval`, XXE, XSS sinks, template/XPath/NoSQL injection, unsigned session cookie, plaintext password | template-file flaws invisible |
| Access control (`access_control.py`, `routes.py`) | route + guard extraction (FastAPI, Flask, Express, Django/DRF, NestJS); IDOR heuristic | global middleware invisible |
| Business logic (`business_logic.py`, `intent.py`, `workflow.py`) | mass assignment, client-trusted values, workflow-order, declared intent rules | Python only, handler-local, stays `suspicious` |
| Misconfiguration / IaC (`misconfig.py`) | Flask/FastAPI/Django flags; Dockerfile, compose, Kubernetes, Terraform | regex on manifest text |
| Logging (`logging_checks.py`) | secrets in logs, swallowed exceptions | |

### 6.2a Hardening recommendations (ADR-045)

`hardening.py` applies 16 fixed rules to the scan's code facts (detected controls, data-category names,
routes, dependencies) and an optional declared profile (purpose, expected users, data categories, regions,
exposure). Output items have a priority (`recommended`/`consider`) but never a severity, cite their
evidence, give a rule-specific "could not verify" note, and never enter totals, SARIF, baselines or gating.
Profile values are never inferred; rules that need a missing field are listed instead of guessed.
Compliance appears only as a "may apply" note. Evaluation status: not evaluated; no usefulness claim is made.

### 6.3 Source-audit pipeline (web app, LangGraph, ADR-016)

authorization gate -> reconnaissance -> scanner -> fix verification -> validator -> *AI validator (opt-in)* ->
correlation -> *AI summary (opt-in)* -> report. Progress is persisted per stage in
`security_audits.stage_state`, so a failed audit can **resume from the failed stage**; interrupted audits are
swept on restart. Findings are owner-scoped; owners can mark false positives (reversible, reasoned).

### 6.4 Live-target pipeline (ADR-003, 044)

authorization_check -> target_validation -> reconnaissance -> attack_surface_processing ->
vulnerability_scanning -> (findings? safe_validation -> validator) -> report_generation -> persist_results.
Five agents: Reconnaissance, Vulnerability Scanner, Safe Validation (the brief's "Exploitation Agent",
renamed because it is non-destructive), Validator, Report. Gate nodes are fatal; tool nodes are non-fatal.
Live findings reuse the same `Vulnerability` table, so the findings UI is shared.

### 6.5 Security model (`docs/security-model.md`)

- Authorization record must postdate the last target change; checked at API, workflow gate and inside every
  tool call.
- Target validation: http/https only, no URL userinfo, resolve and check **every** address (loopback,
  private, link-local, CGNAT, cloud metadata blocked), allow-list, scope, per-request re-resolution, manual
  redirect checking per hop.
- No `shell=True`; argv-only subprocesses; timeouts, rate and output caps; Nuclei intrusive/DoS tags excluded.
- Validation is non-destructive: inert markers, no exploit payloads.

### 6.6 AI layer (all opt-in, advisory)

| Feature | Safeguards |
|---|---|
| `secureagent review` | consent or `--yes`, `--dry-run`, key from env, redaction, quote verification, cache; secret findings never sent |
| AI validator stage | per-audit consent, operator-held key, 15 most severe findings, cannot change status/gate |
| AI narrative stage | code-free fact sheet, over-claim filter, labelled, falls back to deterministic summary |
| MCP server | assistant is the LLM; tools are deterministic and read-only; opt-in verdict recording |

Live runs so far: one `codestral-latest` audit (15/15 findings reviewed, 13 true positive at 0.8-0.9) and one
single-finding CLI call. Accuracy of the AI layer has **not** been measured.

### 6.7 Data model and API

Eight base tables (users, targets, authorization_records, security_audits, reconnaissance_results,
vulnerabilities, security_reports, audit_logs) plus source-project tables; three migrations at last record.
API groups: `/api/auth/*`, `/api/projects/*` (register, zip upload, authorize, revoke), `/api/audits/*`
(create, list, detail, findings, logs, report HTML/PDF, retry/resume, triage, per-finding fix),
`/api/targets/*` (register, authorize, readiness, start audit), `/api/health`. Details: `docs/api.md`,
`docs/database.md`.

### 6.8 Frontend and desktop

Next.js pages: login, register, dashboard, run (unified upload/authorize/start), projects, audits (+ detail
with progress, findings, taint paths, chains, suggested fix), targets (+ detail), settings. Electron shell
(`desktop/`) starts Docker Compose, waits for `/api/health`, and loads the web app; Docker stays the runtime.

## 7. Delivery surfaces

| Surface | Entry |
|---|---|
| CLI | `secureagent [PATH]`, `scan`, `fix`, `suppress`, `review`, `benchmark`, `demo` |
| CI | `--baseline`, `--fail-on`, `--since`, SARIF; composite `action.yml` (SARIF upload, SBOM artifact, one updated PR comment, gate applied last) |
| MCP | `secureagent-mcp`: `scan_snippet`, `scan_path`, `scan_diff`, `suggest_fixes`, `application_model`, `authorization_matrix`, `explain_finding`, opt-in `record_verdict` |
| Editor | `vscode-extension/` runs on save via SARIF |
| Web / desktop | Docker Compose stack; Electron window |

## 8. Engineering process and quality assurance

- 45 ADRs record each decision, including corrections (ADR-036 retracts a claimed taint gap that did not exist).
- Requirement traceability R1-R69 (`docs/REQUIREMENTS_TRACEABILITY.md`); acceptance tally at last full
  count: 15 done, 7 source-only, 6 partial, 0 not built (before ADR-043/044 work).
- Dogfooding: the project scans itself in CI; this found a clean-install crash and an un-scanned lockfile
  type. Dependency bumps follow self-scan findings.
- Tests: 661 backend, 2 skipped (about 93 % line coverage at an earlier count), 43 Vitest, 7 Playwright; a CI job runs
  the full Docker stack. A live audit test runs against a real local HTTP server and yields a genuinely
  `confirmed` finding.
- Test counts above are from project documents, not re-run for this file.

## 9. Evaluation (what is measured and how far to trust it)

| Experiment | Result | Independence |
|---|---|---|
| Author benchmark (`secureagent benchmark`) | 98 % / 98 % at ADR-043 (was 97 % precision, 95 % recall) | **No**: tuned against it; regression guard only |
| Real-project precision, development sample (8 projects, 111 findings) | 28 % before fixes, 82 % after | Guided the fixes |
| Holdout (14 projects) | 59 % before, 83 % after | Partly seen |
| Third set (23 projects, 42 findings) | **48 %** before its fixes, 56 % after | Untouched; the honest figure |
| Recall, 5 public vulnerable apps (42 planted flaws) | 52 % untouched, 79 % / 95 % after fixes | 52 % only |
| Held-out pygoat + Juice Shop (47) | 49 % (pygoat 73 %, Juice Shop 28 %) | Truth list committed before scan |
| Untouched sets 3-11 | 41, 46, 58, 68, 75, 53, 93, 58, 65 % | No detector changed per set |
| **Pooled, 11 untouched sets** | **199/361 = 55 %** | Best independent recall estimate |

Caveats the paper must state:

- **Labeller:** precision labels were assigned by Claude, not a human; no inter-annotator agreement exists.
- **Truth lists** were written by the tool's author (with a model); ADR-036 found five line-number errors
  that had been counted as misses. Match rule: same file, matching type, within 3 lines.
- **Planted-flaw apps** are denser and simpler than production code; recall is not a production rate.
- **No baseline comparison** (Semgrep, Bandit, CodeQL, ESLint security) has been run.
- **No user study** supports the triage-effort or chain-usefulness claims.
- **LLM layer accuracy and hallucination rate** are unmeasured.
- **Precision of newer structural rules** was only spot-checked; some structural rules fire without proof
  the value came from a request (e.g. CLI `input()` flagged).
- **Live pipeline:** ZAP verified against Juice Shop (200 alerts, 131 s, two real bugs found and fixed);
  Nuclei only its graceful-degradation path; live audits cannot resume from a failed stage.
- **Hardening recommendations** (ADR-045) have no usefulness evaluation. Their data-category signals are
  name-based; an audit of the first build found three false triggers (`token_expiry` read as card data,
  `pin_code` as a credential, test fixtures as application data), fixed with regression tests.

Reproduce: `python -m app.evaluation prepare REPO... --out DIR`, label `labels.json`, then
`python -m app.evaluation score`; recall: `python -m app.evaluation recall --apps DIR` with
`backend/benchmark/known_vulnerable.json`. Applications are cloned on demand at pinned commits, never vendored.

## 10. Limitations

- Static analysis cannot prove exploitability; findings are at most `likely`.
- Python analysis is AST-based; JS/TS is regex-based; no template-file (`.html`) analysis; no
  cross-handler mutable-state modelling (stored XSS via a global list).
- Global middleware and base querysets are invisible to unguarded-route and IDOR checks.
- Business-logic detection is Python-only and handler-local.
- OSV matching uses pinned lockfile versions only.
- Single backend replica, in-process login throttling and job runner (ADR-005).
- Fix patches are verified by parse + re-scan, not by behaviour preservation; seven finding types only.

## 11. Threats to validity

Internal: tool tuned on the same projects used to evaluate (mitigated by untouched sets, not eliminated);
one author for tool, benchmark and truth lists; model-labelled precision. External: small, public,
intentionally vulnerable corpora; Python/JS only. Construct: line-tolerance matching can credit a nearby
unrelated finding or miss a correct one; "found" does not mean useful to a developer.

## 12. Ethics and disclosure

The tool never executes scanned code and ships no exploit payloads. Source audits require a recorded
authorization; live scans require authorization plus target validation. Third-party projects should be
reported in aggregate unless maintainers agree; any real vulnerability found must follow responsible
disclosure. Per-finding label sheets contain code and stay out of version control.

## 13. Related-work map (to be filled with citations)

SAST and taint analysis (CodeQL, Semgrep, Bandit, Joern); authorization / BOLA detection; vulnerability
benchmarks (OWASP Benchmark, Juice Shop, CVEfixes); automated program repair for security; LLM-assisted
triage and hallucination in code review; SBOM and OSV; MCP tool ecosystems. No citations were added here:
every reference must be verified before use.

## 14. Suggested paper framings

1. **Tool paper (4-6 pages):** system, honesty model, verified fixes, MCP/CI integration, candid evaluation.
2. **Empirical short paper:** "When the benchmark flatters the tool": 97 % on the author corpus vs. 28-48 %
   precision and about 55 % pooled untouched recall.

## 15. Before submission

Two human annotators with Cohen's kappa; a baseline run against Semgrep/Bandit on the same projects; an
ablation of precision mechanisms; a patch-correctness review; the LLM-layer evaluation if claimed; archive
code, labels and scoring scripts with a DOI; re-run all tests and the benchmark and record versions.

## 16. Where to find detail

| Topic | File |
|---|---|
| Inventory | `docs/OVERVIEW.md` |
| Architecture, agents, security | `docs/architecture.md`, `docs/agent-workflow.md`, `docs/security-model.md` |
| Detectors | `docs/static-analysis.md`, `docs/business-logic-engine.md` |
| Evaluation | `docs/evaluation.md`, `docs/benchmark.md`, ADR-021..041 |
| Paper plan | `docs/paper/PAPER_PLAN.md` |
| History / state | `PROJECT_CHANGELOG.md`, `PROJECT_MEMORY.md` |
