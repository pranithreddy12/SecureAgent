# SecureAgent – Application Security Auditor

SecureAgent helps developers find and fix vulnerabilities in **their own** applications —
including the logic flaws that pattern-matching scanners miss — before an attacker does.
It reads your source (it never executes it), explains *why* each finding was flagged, correlates
findings into attack chains, proposes verified fixes, and reports honestly.

> **Use only on systems and source code you own or are explicitly authorized to test.**

## Try it on your own project (two commands)

```bash
pip install "git+https://github.com/pranithreddy12/SecureAgent.git#subdirectory=backend"
```

```bash
cd /path/to/your/project && secureagent
```

That scans the current directory (read-only) and **opens the HTML report in your browser**.
`secureagent PATH` does the same for another folder. Needs Python 3.12+; no database, no Docker.
The report is written to your temp directory, not into your project.

## What it is (and is not)

**Delivered as a grey-box static security auditor** (owner decision, ADR-014): a deterministic engine
plus optional, advisory AI layers. The original brief's *live-target* pipeline (URL targets, live
reconnaissance, OWASP ZAP, Nuclei, exploit-style validation) is designed but deliberately **not** built.
The complete inventory, with evidence and limits, is in [docs/OVERVIEW.md](docs/OVERVIEW.md); the verdict
against the original 28 acceptance criteria (15 done, 7 done for source audits only, 6 partial, 0 not
built) is in [docs/PROJECT_CLOSEOUT.md](docs/PROJECT_CLOSEOUT.md).

## What it finds

All static and read-only. Findings are `likely` / `suspicious` / `informational` — static analysis alone is
never `confirmed`, and CVE/CVSS appear only from real advisory data.

| Area | Examples |
|---|---|
| Secrets | provider keys, hardcoded credentials (always redacted; git-ignored files shown as informational) |
| Dependencies | known vulnerabilities via OSV, with CVSS v3 computed from the advisory's own vector |
| Injection | SQL / command / code / SSRF / path traversal / open redirect, by data flow across helpers and files, **with the source→sink path shown** |
| Access control | IDOR, unguarded routes (FastAPI, Flask, Express, Django/DRF, NestJS), inconsistent guards, **authorization matrix** |
| Business logic | mass assignment, client-trusted prices/roles, workflow-order gaps, your own rules via an **intent spec** |
| Correlation | **attack chains**: an unguarded route that reaches an injection, credentialed CORS + CSRF off |
| Misconfiguration | debug mode, CORS, JWT verification, CSRF, cookies; secrets in logs, swallowed exceptions; root containers, CSP `unsafe-inline`, unbounded exports |
| More classes | template / XPath / NoSQL injection, reflected XSS, unsigned session cookies, plaintext passwords, JavaScript IDOR (heuristic, see `docs/evaluation.md`) |

## The commands

```bash
secureagent                                   # scan "." and open the report
secureagent scan . --report report.html       # report (add --pdf for PDF)
secureagent scan . --matrix --recon           # route x guard matrix; technologies, inputs, hosts
secureagent scan . --since origin/main        # only findings NEW compared with a git ref (PR review)
secureagent scan . --baseline .secureagent-baseline.json --fail-on high   # CI gate on new high+
secureagent scan . --format sarif --output secureagent.sarif              # GitHub code scanning
secureagent fix .                             # verified patches as diffs (--apply writes them)
secureagent suppress . --list                 # findings with short ids
secureagent suppress . --id 3f9a1c0b --reason "cache key only" --expires 2027-01-01
secureagent review . --dry-run                # LLM second opinion: show exactly what would be sent
secureagent demo                              # a labelled, deliberately vulnerable sample app
secureagent benchmark backend/benchmark/corpus
```

Suppression is never silent: excluded files and `# secureagent: ignore` lines are counted in the output;
justified suppressions live in a reviewable `secureagent-suppressions.json`.

## Use it from Claude Code (MCP)

```bash
claude mcp add secureagent -- secureagent-mcp
```

Tools: `scan_snippet` (check code you just wrote), `scan_path`, `scan_diff`, `explain_finding` (judge one
finding with its code and taint path), `suggest_fixes`, `application_model`, `authorization_matrix`. Read-only, confined to the working directory, offline by default.
See [docs/mcp.md](docs/mcp.md).

## The web application

```bash
cp .env.example .env            # set SECRET_KEY (>= 32 chars) and POSTGRES_PASSWORD
mkdir -p workspace && cp -r /path/to/project workspace/myapp     # mounted read-only at /workspace
docker compose up --build -d backend frontend                    # http://localhost:3000
```

Register a project (a mounted directory, or **upload a zip** -- unpacked safely into a private folder and
deleted with the project), confirm authorization (append-only, revocable), start an audit, watch the staged
pipeline (LangGraph; authorization gate → reconnaissance → scanner → fix verification → validator →
correlation → report, plus two **opt-in** AI stages), and download the HTML/PDF report. Failed audits can be
retried or resumed from the failed stage, and any finding can be marked a false positive with a recorded
reason (reversible). Set `LLM_API_KEY` to offer the optional AI review/summary.
Details: [docs/deployment.md](docs/deployment.md).

### As a desktop app, not a browser tab

```bash
cd desktop && npm install && npm start
```
Starts the Docker stack for you and opens it in a native window (title bar, app menu, a branded splash
while the backend comes up) instead of a browser tab. See [desktop/README.md](desktop/README.md) and
[ADR-038](docs/adr/ADR-038-desktop-shell.md).

## Honesty and safety model

- Read-only: scanned code is never executed; paths are confined to `SOURCE_ROOTS`.
- Findings are never `confirmed` by static analysis; chains never exceed their worst member's severity.
- Secrets are redacted everywhere and never sent to an LLM.
- AI is **opt-in, consented and advisory**: it cannot change a finding's status, the baseline or the CI gate,
  and its evidence quote must exist in the code that was sent.
- Authentication: Argon2id, JWT in an httpOnly cookie, login throttling, owner-scoped data.

## Known limitations

- Python is analysed deeply; JavaScript/TypeScript is regex-based and shallower.
- Global middleware and framework defaults are invisible, so "unguarded" findings are review items.
- Detector accuracy is measured on an **author-written** corpus (97% / 95%). On real projects the first
  sample was 28% precise; after fixes the same sample is ~82% (a holdout ~83%), but a third, untouched set
  measured **48%** before its own fixes. Labels are a model's first pass, not independently verified
  (`docs/evaluation.md`). Against planted flaws in public vulnerable apps the scanner found about half
  (52%, 49%, 41%, 46%, 58%, 68%, 75%, 53%, 93%, 58% and 65% on eleven untouched batches, ten of them
  corrected 2026-10-14 after five truth-list line errors were found, ADR-036; pooled 55%) before any change;
  after fixes
  tuned on the earlier sets it finds 80% over all 226, which is not an independent figure. LLM accuracy is unmeasured.
- Zip upload accepts `.zip` only, with size/file-count limits; triage is per audit (use
  `secureagent suppress` for a rule that applies to future audits).
- Login throttling and the interrupted-audit sweep assume a single API replica.

## Tests

```bash
make testdb                              # throwaway PostgreSQL (needs Docker)
cd backend && python -m pytest -q        # 570 passed, 2 skipped
cd frontend && npm run lint && npm run typecheck && npm test && npm run build   # 40 unit tests
cd frontend && npm run e2e               # 7 Playwright tests against the Docker stack
```

CI runs four jobs on every push: backend (lint + tests), frontend, SecureAgent scanning itself, and e2e.

## Documentation

| Topic | Document |
|---|---|
| **How to run it (CLI, web app, MCP)** | [docs/MANUAL.md](docs/MANUAL.md) |
| **Everything that was built** | [docs/OVERVIEW.md](docs/OVERVIEW.md) |
| Verdict against the original brief | [docs/PROJECT_CLOSEOUT.md](docs/PROJECT_CLOSEOUT.md) |
| Current state / history / decisions | [PROJECT_MEMORY.md](PROJECT_MEMORY.md), [PROJECT_CHANGELOG.md](PROJECT_CHANGELOG.md), [docs/adr/](docs/adr/) (39 ADRs) |
| Original baseline requirements | [SPECIFICATION.md](SPECIFICATION.md) |
| Requirement-to-code mapping | [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) |
| Detector behaviour and limits | [docs/static-analysis.md](docs/static-analysis.md), [docs/business-logic-engine.md](docs/business-logic-engine.md) |
| Accuracy, benchmark, paper plan | [docs/benchmark.md](docs/benchmark.md), [docs/paper/PAPER_PLAN.md](docs/paper/PAPER_PLAN.md) |
| MCP, deployment, API, testing, demo | [docs/mcp.md](docs/mcp.md), [docs/deployment.md](docs/deployment.md), [docs/api.md](docs/api.md), [docs/testing.md](docs/testing.md), [docs/demo-guide.md](docs/demo-guide.md) |
| Architecture, security model, UML | [docs/architecture.md](docs/architecture.md), [docs/security-model.md](docs/security-model.md), [docs/diagrams/](docs/diagrams/) |

## Technology

Python 3.12 · FastAPI · Pydantic · SQLAlchemy 2 (async) · Alembic · PostgreSQL · LangGraph · Jinja2 +
WeasyPrint · Next.js 16 / React / TypeScript / Tailwind · Docker Compose · Vitest · Playwright.
Standards: OWASP Top 10, CWE, CVE (via OSV), CVSS v3 (computed from published vectors).

## License

MIT — see [LICENSE](LICENSE).
