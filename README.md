# SecureAgent – Multi-Agent AI Application Security Auditor

SecureAgent helps developers find and fix vulnerabilities in **their own** applications —
including the logic flaws that pattern-matching scanners miss — before an attacker does.

> **Use only on systems and source code you own or are explicitly authorized to test.**

## Project status (honest summary)

| Part | State |
|---|---|
| **Static analysis engine + CLI** (`secureagent`) | ✅ Built, tested, usable on real repositories |
| Reports (HTML / PDF / JSON / SARIF), CI baseline & gating, demo | ✅ Built, tested |
| Authentication, PostgreSQL schema + migrations, Docker Compose, frontend login/dashboard shell | ✅ Built, tested |
| **Live audit pipeline**: targets, authorization gate, reconnaissance, OWASP ZAP, Nuclei, safe validation, validator, LangGraph orchestration, audit-progress UI | ⛔ **Designed but not implemented** — blocked on target management (see below) |

The multi-agent live-audit architecture from the project specification is fully designed
(`docs/agent-workflow.md`, `docs/security-model.md`, ADR-001/003/005/008) but its first
prerequisite — target management with the network-safety validator — has not been built.
`docs/target-management-implementation.md` is the hand-off specification for those two files.
Nothing in this repository claims otherwise. See [docs/PROJECT_CLOSEOUT.md](docs/PROJECT_CLOSEOUT.md)
for the complete status against the original requirements.

## What the scanner finds

`secureagent scan` is read-only static analysis (it never executes the scanned code):

- **Hardcoded secrets** — provider keys and high-entropy credentials (always redacted).
- **Vulnerable dependencies** — lockfiles checked against the public [OSV](https://osv.dev) database.
- **Injection by data flow** — untrusted input reaching SQL/command/code/SSRF/path/redirect sinks,
  across helper functions, return values and files (Python), plus a JavaScript/TypeScript heuristic.
- **Broken access control** — IDOR / missing ownership checks, endpoints with no visible
  authorization (FastAPI, Flask, Django/DRF, Express, NestJS).
- **Dangerous code** — insecure deserialization, `shell=True`, `eval`, weak hashing, disabled TLS, XXE.
- **Misconfiguration** — debug mode, wildcard CORS, JWT verification off, CSRF off, insecure cookies.
- **Logging failures** — secrets in logs, swallowed exceptions.

Findings are honest: static analysis alone is never reported as `confirmed`; heuristic ones say
so; CVE/CVSS values are shown only from real advisory data. Coverage maps to OWASP Top 10
A01–A03 and A05–A10 (A04 partially). Details and limits: [docs/static-analysis.md](docs/static-analysis.md).

## Quick start

```bash
cd backend && python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt     # Linux/macOS: .venv/bin/python
pip install -e .                                                # provides the `secureagent` command

secureagent demo                              # no setup: scans a bundled, deliberately vulnerable sample app
secureagent scan /path/to/your/repo           # human-readable
secureagent scan . --report report.html       # professional report (add --pdf for PDF)
secureagent scan . --format sarif --output secureagent.sarif        # GitHub code scanning
secureagent scan . --write-baseline .secureagent-baseline.json      # accept today's findings
secureagent scan . --baseline .secureagent-baseline.json --fail-on high   # CI: fail on NEW high+
secureagent scan . --exclude "tests/" --no-osv                      # skip paths / work offline
```

Suppression is never silent: excluded files and `# secureagent: ignore` lines are counted in the
output. Put patterns in a `.secureagentignore` file at the scan root. See
[docs/demo-guide.md](docs/demo-guide.md) and [docs/ci/github-actions-example.yml](docs/ci/github-actions-example.yml).

## The web application (current state)

```bash
cp .env.example .env        # set SECRET_KEY (>= 32 chars), POSTGRES_PASSWORD, ZAP_API_KEY
docker compose up --build -d      # frontend :3000, backend :8000, postgres, zap
```

Implemented: register / login / logout / current user (Argon2id + JWT in an httpOnly cookie),
dashboard with live backend status, settings. Stack: Next.js 16 + React + TypeScript + Tailwind;
FastAPI + SQLAlchemy 2 + Alembic; PostgreSQL 16. Full instructions: [docs/deployment.md](docs/deployment.md).

## Technology stack

Python 3.12 (3.14 locally) · FastAPI · Pydantic · SQLAlchemy 2 (async) · Alembic · PostgreSQL ·
Jinja2 + WeasyPrint (reports) · Next.js 16 / React / TypeScript / Tailwind · Docker Compose ·
OWASP ZAP and Nuclei (containers/binaries defined, integration pending) · LangGraph/LangChain
(designed, not yet used). Standards: OWASP Top 10, CWE, CVE (via OSV), CVSS (only when supplied).

## Architecture and documentation

| Topic | Document |
|---|---|
| Original baseline requirements | [SPECIFICATION.md](SPECIFICATION.md) |
| Current state / history / decisions | [PROJECT_MEMORY.md](PROJECT_MEMORY.md), [PROJECT_CHANGELOG.md](PROJECT_CHANGELOG.md), [docs/adr/](docs/adr/) |
| Requirement-to-code mapping | [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) |
| **Close-out audit (what is done, what remains)** | [docs/PROJECT_CLOSEOUT.md](docs/PROJECT_CLOSEOUT.md) |
| Architecture, agent workflow, security model | [docs/architecture.md](docs/architecture.md), [docs/agent-workflow.md](docs/agent-workflow.md), [docs/security-model.md](docs/security-model.md) |
| Business-logic engine design (grey-box) | [docs/business-logic-engine.md](docs/business-logic-engine.md) |
| UML diagrams (7, matching the code) | [docs/diagrams/](docs/diagrams/) |
| Database, API | [docs/database.md](docs/database.md), [docs/api.md](docs/api.md) (OpenAPI at `/docs` when running) |
| Testing, deployment, demo | [docs/testing.md](docs/testing.md), [docs/deployment.md](docs/deployment.md), [docs/demo-guide.md](docs/demo-guide.md) |

## Agent architecture (designed)

Five agents orchestrated by LangGraph: Reconnaissance, Vulnerability Scanner (ZAP + Nuclei),
**Safe Validation** (the controlled, non-destructive implementation of the specification's
"Exploitation Agent"), Validator (false-positive reduction) and Report. The static engine in this
repository is the working core that the grey-box design (ADR-008) folds into that pipeline.

## Security model

Authorized testing only. The designed controls (authorization gate at API, workflow and tool
layers; blocking of private/loopback/link-local/metadata targets; scope enforcement; no control
bypass) are specified in [docs/security-model.md](docs/security-model.md); the **network-level
ones are part of the unbuilt target-management work**. Implemented: Argon2id password hashing,
indistinguishable login failures, JWT hardening (alg pinned), ownership-scoped schema, secret
redaction everywhere, read-only scanning, escaped reports.

## Running the tests

```bash
make testdb                      # throwaway PostgreSQL (needs Docker)
cd backend && python -m pytest -q    # 253 tests (252 pass, 1 skipped); ~93% coverage
cd frontend && npm run lint && npx tsc --noEmit && npm run build
```

## Known limitations

- The live audit pipeline, ZAP/Nuclei integration, LLM reasoning and audit-progress UI do not exist yet.
- Static taint is intraprocedural-plus (within/across files, return values) but does not model
  sanitizers and resolves cross-file calls heuristically; JS analysis is regex-based.
- Unprotected-endpoint findings cannot see global middleware, so they are review items.
- Frontend has no automated tests; no login rate limiting; no admin bootstrap; no `LICENSE` yet.

## Future improvements

Target management and the audit pipeline; scheduled/continuous audits; SSE progress streaming;
authenticated scanning with test credentials; deeper dataflow (sanitizer modelling); more languages.

## Academic demonstration

1. `secureagent demo --report demo.html` — a real scan of a deliberately vulnerable fake app, labelled
   *DEMO / SIMULATED SECURITY AUDIT* (script in [docs/demo-guide.md](docs/demo-guide.md)).
2. `secureagent scan backend --exclude tests/` — SecureAgent auditing its own backend, including its
   pinned dependencies against OSV (clean at the time of writing).
3. Walk the UML in [docs/diagrams/](docs/diagrams/) and the honest status table above.
