# SecureAgent -- what was built, in one place

Status: **2026-10-12.** Delivered as a *grey-box static security auditor* (ADR-014). This document is the
inventory: every capability, where it lives, how it is tested, and its honest limit. Day-to-day state is in
`PROJECT_MEMORY.md`; history in `PROJECT_CHANGELOG.md`; the requirement mapping in
`docs/REQUIREMENTS_TRACEABILITY.md`; the verdict against the original brief in `docs/PROJECT_CLOSEOUT.md`.

## 1. The product in one paragraph

SecureAgent reads a developer's own source code (never executing it), finds security flaws -- including
business-logic ones -- explains why each was flagged, correlates findings into attack chains, proposes
verified fixes, and reports honestly (static analysis alone is never "confirmed"). It is usable as a
command-line tool, as a CI gate, from an AI coding assistant over MCP, and as a web application with
persisted audits. An opt-in LLM layer gives second opinions but never has authority over the result.

## 2. Ways to use it

| Interface | Command / entry | For |
|---|---|---|
| **CLI, one command** | `secureagent` (scans `.` and opens the report) / `secureagent PATH` | trying it on a project |
| CLI, explicit | `secureagent scan PATH [--format text/json/sarif] [--report F] [--pdf F] [--matrix] [--recon] [--intent F] [--exclude P] [--no-osv]` | scripting |
| CI gate | `scan --baseline B --fail-on high`, `--write-baseline`, `--since REF`, SARIF output | pull requests, pipelines |
| Fixes | `secureagent fix PATH [--apply]` | verified one-line patches |
| Triage | `secureagent suppress PATH --list` / `--id ID --reason ... [--expires D]` | recording false positives |
| LLM second opinion | `secureagent review PATH [--dry-run] [--yes] [--report F]` (needs `ANTHROPIC_API_KEY`) | judging noisy findings |
| Accuracy | `secureagent benchmark DIR` | measuring precision/recall |
| Demo | `secureagent demo` | a labelled, deliberately vulnerable sample |
| **MCP server** | `secureagent-mcp` -- tools `scan_snippet`, `scan_path`, `scan_diff`, `suggest_fixes`, `application_model`, `authorization_matrix`, `explain_finding` | Claude Code / Claude Desktop |
| **Web app** | Docker Compose; projects, authorization, 9-stage pipeline, history, reports | teams, persisted audits |
| Admin | `python -m app.manage create-admin` | first administrator |

## 3. Detection (all static, read-only)

| Area | What it finds | Notes / limits |
|---|---|---|
| Secrets | provider keys, secret-named high-entropy values (always redacted) | key names matched as *words*; git-ignored files -> informational; client-side Google keys -> low |
| Dependencies | known vulnerabilities via OSV (lockfiles) | CVSS v3 computed from the advisory's vector, never estimated |
| Injection | SQL/command/code/SSRF/path/redirect by taint, across helpers, return values and files | numbered **taint path** per finding; sanitizers (casts, `shlex.quote`, allow-list guards); JS is regex-based |
| Dangerous code | deserialization, `shell=True`, `eval`, weak hash, disabled TLS, XXE / entity expansion, XSS sinks | stdlib XML = entity expansion (low), not XXE |
| Access control | IDOR, unguarded routes (FastAPI, Flask, Express, Django/DRF, NestJS) | guards recognised at decorator, signature, **router**, **route-level**, **include_router** and **in-handler** level; global middleware is invisible |
| **Business logic** | mass assignment, client-trusted privilege/price fields, workflow-order (state set without a precondition) | Python only; heuristics, `suspicious` |
| **Intent spec** | developer rules (`require_auth`, `owner_scoped`, `never_from_client`) checked against the code | `secureagent-intent.json` |
| Authorization matrix | route x guard grid; unguarded outliers among guarded siblings | public reads with guarded writes are not flagged |
| **Attack chains** | unguarded route + injection/IDOR/privilege fields; credentialed CORS + CSRF off | severity = worst member, never escalated |
| Misconfiguration / logging | debug, CORS, JWT, CSRF, cookies; secrets in logs, swallowed exceptions | |
| Reconnaissance | technologies, inputs read, outbound hosts, env vars | source only; **not** live recon |

## 4. Trust and honesty mechanisms

| Mechanism | Behaviour |
|---|---|
| Status model | `likely` / `suspicious` / `informational` / `false_positive`; static findings are never `confirmed` |
| Validation rules | test/example/dev-only code and git-ignored files -> `informational` (reason recorded); they do not drive risk, chains or gates |
| Suppressions | justified (>= 10 chars), expiring, count-capped; become `false_positive` with the reason |
| Baseline / diff | line-independent fingerprints; `--since` reports only new findings |
| Verified fixes | a patch is "verified" only if it parses and a re-scan shows the finding gone and nothing new |
| Redaction | secret values never appear in output; secret findings are never sent to an LLM |
| AI layer | opt-in, consented, quote-verified, advisory only (see section 6) |

## 5. The web application

| Piece | Detail |
|---|---|
| Auth | Argon2id, JWT in an httpOnly cookie, login throttling (429), admin bootstrap |
| Projects | register a directory under `SOURCE_ROOTS` **or upload a zip** (safe extraction, private folder, deleted with the project); append-only revocable authorization; per-user limits |
| Audits | owner-scoped; per-user concurrency limit; retry (clean) or **resume from the failed stage**; interrupted audits swept on restart |
| Pipeline | LangGraph: authorization gate -> reconnaissance -> scanner -> fix verification -> validator -> *AI validator (opt-in)* -> correlation -> *AI summary (opt-in)* -> report |
| Outputs | progress polling, findings with taint paths, attack chains, authorization matrix, activity log, HTML/PDF report; **mark as false positive** (owner, reasoned, reversible) |
| UI | `/projects`, `/audits`, `/audits/[id]`, dashboard with real counts |
| Stack | FastAPI, SQLAlchemy 2 (async), Alembic (3 migrations), PostgreSQL, Next.js 16, Docker Compose |

## 6. The AI features (all opt-in, advisory)

| Feature | Where | Safeguards |
|---|---|---|
| `secureagent review` | CLI | consent or `--yes`, `--dry-run`, key from env, redaction, quote verification, cache |
| AI validator stage | web pipeline | per-audit consent, operator-held key, 15 most severe findings, never changes status/gate |
| AI narrative stage | web pipeline | code-free fact sheet, over-claim filter, labelled, falls back to the deterministic summary |
| MCP | `secureagent-mcp` | Claude Code is the LLM; our tools are deterministic and read-only |

**Not evaluated:** no live provider call has been run by the project (fake transport), and the precision
gain / hallucination rate is unmeasured (paper RQ5).

## 7. Evidence

| | |
|---|---|
| Backend tests | 521 passed, 2 skipped (PDF locally, Windows symlink) |
| Frontend | 39 Vitest tests; lint, typecheck, build |
| Browser e2e | 7 Playwright tests against the Docker stack (own CI job) |
| CI | 4 jobs on every push: backend, frontend, self-scan, e2e |
| Benchmark | 35 TP / 1 FP / 2 FN = 97% precision, 95% recall on an **author-written** corpus (a regression guard, not a real-world rate) |
| Independent signal | 28% precision on a stratified sample of eight real projects (before fixes), ~82% on the same items after, ~83% on a 14-project holdout; labelled by a model, not verified by a human -- see `docs/evaluation.md` |
| Self-scan | clean apart from one accepted dev-only advisory (`braces`) |

## 8. What does **not** exist

- Live-target auditing: URL targets, network-safety validation, live reconnaissance, ZAP, Nuclei,
  exploit-style validation (ADR-014, ADR-015). Acceptance criteria are tracked honestly in
  `docs/PROJECT_CLOSEOUT.md`.
- Languages other than Python (deep) and JS/TS (shallow, regex-based).
- Any measured real-world detection rate or LLM accuracy.
- Per-user LLM keys in the web app (one operator key).

## 9. Architecture decisions

| ADR | Decision |
|---|---|
| 001 | LangGraph orchestration; the LLM never routes |
| 002 | PostgreSQL + SQLAlchemy 2 async + Alembic |
| 003 | Safe (non-destructive) validation instead of exploitation |
| 004 | Demo mode labelled everywhere |
| 005 | In-process asyncio jobs + polling |
| 006 | Argon2id + JWT httpOnly cookie |
| 007 | Pydantic context -> Jinja2 HTML -> WeasyPrint PDF |
| 008 | Grey-box: source + developer intent for business-logic flaws |
| 009 | CLI is dependency-light (stdlib + jinja2 + pydantic) |
| 010 | Business-logic detectors and the intent spec |
| 011 | Persisted source audits (no live target) |
| 012 | Attack chains as an interpretation layer |
| 013 | Verified fix patches |
| 014 | Close as a grey-box static auditor (live pipeline deferred) |
| 015 | Static reconnaissance and rule-based validation |
| 016 | Source-only agent pipeline (phases 4-12) |
| 017 | Opt-in LLM review |
| 018 | Opt-in AI validator and narrative stages |
| 019 | Zip upload, owner triage, MCP `explain_finding` |
| 020 | MCP trust layer, opt-in verdict recording, detector gaps |
| 021 | Real-project evaluation harness and the fixes it drove |

## 10. Document map

| Need | Read |
|---|---|
| Use it | `README.md`, `docs/demo-guide.md`, `docs/mcp.md`, `docs/deployment.md` |
| Detector behaviour and limits | `docs/static-analysis.md`, `docs/business-logic-engine.md` |
| Accuracy and the paper | `docs/benchmark.md`, `docs/paper/PAPER_PLAN.md` |
| Design and security model | `docs/architecture.md`, `docs/security-model.md`, `docs/diagrams/`, `docs/adr/` |
| API and data | `docs/api.md`, `docs/database.md` |
| Verdict and gaps | `docs/PROJECT_CLOSEOUT.md`, `docs/REQUIREMENTS_TRACEABILITY.md` |
| Day-to-day context | `PROJECT_MEMORY.md`, `PROJECT_CHANGELOG.md` |
