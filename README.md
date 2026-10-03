# SecureAgent – Multi-Agent AI Application Security Auditor

Multi-agent AI platform for auditing **authorized** web applications and APIs:
reconnaissance, scanning (OWASP ZAP, Nuclei), safe non-destructive validation,
false-positive reduction, OWASP/CWE/CVE/CVSS mapping and professional reports.

It is becoming a **grey-box** tool: alongside dynamic testing, it analyses the
application's **own source code** plus a short developer description to find complex
**business-logic** vulnerabilities that pattern scanners miss (see
[ADR-008](docs/adr/ADR-008-grey-box-business-logic.md) and
[docs/business-logic-engine.md](docs/business-logic-engine.md)).

## Usable now: static secret scanner

The static analysis engine works today, standalone (no database or server). It scans a
source tree you own or are authorized to audit and reports three classes of real issue:

- **Hardcoded secrets** — API keys, tokens, private keys, credentials (redacted on output).
- **Vulnerable dependencies** — declared packages checked against the public
  [OSV](https://osv.dev) vulnerability database (real advisory IDs only).
- **Endpoints without visible authorization** — HTTP routes (Python/JS) that change
  data or look privileged with no detected auth guard (low-confidence review items).

```bash
cd backend
python -m app.cli scan /path/to/your/repo                         # human-readable
python -m app.cli scan /path/to/your/repo --format json --output findings.json
python -m app.cli scan /path/to/your/repo --report report.html    # professional report
python -m app.cli scan /path/to/your/repo --no-osv                # offline (skip OSV)
```

It only reads files — it never executes anything from the scanned project — never
prints or stores a secret's full value (only a masked preview and a fingerprint), and
exits non-zero when findings exist, so it can gate CI.

- Baseline requirements: [SPECIFICATION.md](SPECIFICATION.md)
- Current state: [PROJECT_MEMORY.md](PROJECT_MEMORY.md)
- History: [PROJECT_CHANGELOG.md](PROJECT_CHANGELOG.md)
- Design: [docs/](docs/)

**Use only against systems and code you are authorized to test.**
