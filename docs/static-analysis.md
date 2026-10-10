# SecureAgent – Static Analysis Engine

Status: **Implemented & tested** (2026-10-08). This is the working core of SecureAgent
today: a standalone, read-only static application-security scanner for source code you
own or are authorized to analyse. It needs no database or server.

## Running it

```bash
cd backend
python -m app.cli scan /path/to/repo                 # or: pip install -e . ; secureagent scan ...
python -m app.cli scan /path/to/repo --format json|sarif --output findings.ext
python -m app.cli scan /path/to/repo --report report.html --pdf report.pdf
python -m app.cli scan /path/to/repo --baseline bl.json --fail-on high   # CI gate
```

Exit codes: `0` clean / gate passed, `1` findings (or new findings ≥ `--fail-on`),
`2` error.

## Safety

- **Read-only.** Files are only read; nothing in the scanned project is executed,
  imported, or installed.
- **Secrets are redacted.** A secret's full value is never printed, stored or sent —
  only a masked preview and a non-reversible fingerprint.
- **Bounded.** Vendored/VCS/binary files are skipped; size, file-count and total-byte
  limits apply.
- **OSV lookups** send only package names and versions (never code); `--no-osv` runs
  fully offline.

## Detectors (`backend/app/analysis/`)

| Module | Detects | Standard |
|---|---|---|
| `secrets.py` | Hardcoded credentials, API keys, private keys (provider signatures + entropy), redacted | CWE-798 / A05 |
| `dependencies.py` + `osv.py` | Declared dependencies with known advisories (OSV) | CWE-1104 / A06 |
| `sinks.py` | Insecure deserialization, command/code exec, weak hashing, disabled TLS, insecure temp, XXE, JS XSS sink | A02/A03/A05/A08 |
| `taint.py` | **Injection via data flow** (SQLi, command, code, SSRF, path traversal, open redirect) — interprocedural within a file (Python) + JS/TS heuristic | A03/A10/A01 |
| `access_control.py` | IDOR / missing object-level authorization | CWE-639 / A01 |
| `business_logic.py` | Mass assignment, client-trusted privilege/value (ADR-010) | CWE-915, 269, 602 / A01, A04 |
| `authz_matrix.py` | Route x guard grid by resource; unguarded outliers among guarded siblings (`scan --matrix`) | CWE-862 / A01 |
| `intent.py` | Developer intent spec (`secureagent-intent.json`) checked against routes + IDOR | CWE-862, 639 / A01 |
| `misconfig.py` | Debug on, permissive CORS, disabled JWT verification, CSRF off, autoescape off, wildcard hosts, insecure cookies | A05/A07 |
| `logging_checks.py` | Sensitive data in logs (CWE-532), swallowed exceptions (CWE-778) | A09 |
| `routes.py` | HTTP routes + endpoints lacking a visible authorization guard | CWE-862 / A01 |

Orchestration: `scanner.py` (`scan_repo` → `ScanResult`); `reporting.py`
(`scan_to_report_context` → shared `ReportContext`); `baseline.py` (fingerprints, CI
gating); `sarif.py` (SARIF 2.1.0); `app/reports/renderer.py` (HTML/PDF).

## Controlling noise (suppression)

```bash
secureagent scan . --exclude 'tests/' --exclude '*.min.js'   # glob patterns; 'dir/' excludes a tree
```

- A `.secureagentignore` file at the scan root holds the same patterns (one per line, `#` comments).
- A `secureagent: ignore` comment (any comment syntax, case-insensitive) hides findings reported on that
  line; put the reason in a comment above. The marker must be on the line the finding is reported at.
- Suppression is never silent: excluded files and inline-ignored findings are counted in the text and
  JSON output. Use a baseline (`--baseline`) to accept existing findings and gate only on new ones.
- Lockfiles recognised: `requirements*.txt|.in|.lock`, `requirements/<name>.txt`, `Pipfile.lock`,
  `poetry.lock`, `package-lock.json`. Pin versions (`==`) so the OSV check has something to match.

## OWASP Top 10 coverage

| Category | Status |
|---|---|
| A01 Broken Access Control | ✅ IDOR, missing-authz, path traversal, open redirect |
| A02 Cryptographic Failures | ✅ weak hashing, disabled TLS |
| A03 Injection | ✅ data-flow taint (SQLi/cmd/code) + dangerous sinks |
| A04 Insecure Design | ◐ partial (client-trusted values, mass assignment, declared intent rules; no workflow-order yet) |
| A05 Security Misconfiguration | ✅ debug, CORS, CSRF, autoescape, hosts, XXE |
| A06 Vulnerable Components | ✅ OSV |
| A07 Identification & Auth Failures | ✅ JWT verification |
| A08 Software & Data Integrity | ✅ insecure deserialization |
| A09 Logging & Monitoring Failures | ✅ sensitive data in logs, swallowed exceptions |
| A10 SSRF | ✅ data-flow taint |

## Honesty model

Findings carry a status: **confirmed** is never produced by static analysis alone.
Definite misconfigurations (weak crypto, disabled TLS, debug on) are **likely**;
input-dependent sinks and heuristic access-control findings are **suspicious** with a
confidence score. CVE/CVSS are shown only from real advisory metadata — never invented.

## Known limitations

- Python taint also follows **return values** of local helpers (within a file).
- Python taint is interprocedural **within a file**, flow-insensitive, and does not
  model sanitizers (can over-report; may miss cross-file flows).
- JS/TS analysis is a file-scoped regex heuristic (no JS AST), coarser than Python.
- Route extraction covers FastAPI/Flask, Express, Django (DRF + class-based views)
  and NestJS. IDOR/taint cover FastAPI/Flask, DRF function views and Django class-based
  views (get_queryset owner-scoping recognised). Global/middleware auth is invisible, so those are low-confidence.
- OSV matching uses declared lockfile versions (no transitive range resolution);
  requires network (graceful offline skip).

## Tests

`backend/tests/test_{secret_scan,dependencies,sinks,taint,taint_deep,access_control,`
`misconfig,route_scan,baseline,sarif,reports}.py` — 114 passing, 1 skipped (PDF, needs
WeasyPrint native libraries available in the Docker image).

## Measured accuracy

`secureagent benchmark` scores the detectors against a labelled corpus; see [benchmark.md](benchmark.md).

## Developer intent spec (business logic)

Put a `secureagent-intent.json` in the repository root (or pass `--intent FILE`) to state what the code
must enforce; SecureAgent reports where the source does not show it (ADR-010):

```json
{"rules": [
  {"id": "admin-requires-auth", "type": "require_auth",      "paths": ["/admin/*"]},
  {"id": "orders-are-private",  "type": "owner_scoped",      "paths": ["/orders/*"]},
  {"id": "no-client-tenant",    "type": "never_from_client", "fields": ["tenant_id"]}
]}
```

Findings are `suspicious`, never `confirmed`: a guard applied by middleware the analyser cannot see
will still produce a violation to review. A malformed spec stops the scan with exit code 2.
