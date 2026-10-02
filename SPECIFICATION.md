# SecureAgent – Specification (Original Baseline)

> **Status:** ORIGINAL BASELINE. Do not rewrite this file when requirements change.
> Record changes in `PROJECT_MEMORY.md` (§15 Scope Changes) and `PROJECT_CHANGELOG.md`.
>
> **Source note (2026-10-02):** The project PPT was **not available** when this file was
> created. By the project owner's decision, this baseline was extracted from the
> project owner's written brief (which summarises the PPT). Sections the brief does not
> cover are marked **PENDING – PPT not provided**. When the PPT is supplied, fill
> those sections in **only** (append-style), record the fill-in in the changelog, and
> flag any conflict between the PPT and this file in `PROJECT_MEMORY.md` §16.

---

## 1. Project Title

**SecureAgent – Multi-Agent AI Application Security Auditor**

Type: Major academic project / working security platform.

## 2. Abstract

SecureAgent is a web-based, multi-agent AI platform that audits **authorized** web
applications and APIs. It combines AI reasoning (LangGraph / LangChain agents) with
established deterministic security tools (OWASP ZAP, Nuclei) to perform
reconnaissance, vulnerability detection, safe (non-destructive) validation of
suspected vulnerabilities, false-positive reduction, classification against security
standards (OWASP Top 10, CWE, CVE/NVD, CVSS), remediation guidance, and
developer-friendly professional reporting.

*Full PPT abstract text: PENDING – PPT not provided.*

## 3. Objective

Build a real, working platform that lets an authorized user:

1. Register / log in.
2. Create a security-testing target.
3. Confirm authorization to test the target.
4. Validate target scope.
5. Start an audit.
6. Perform reconnaissance.
7. Discover endpoints, APIs, technologies, forms and attack surface.
8. Scan for potential vulnerabilities.
9. Safely validate suspected vulnerabilities.
10. Verify findings.
11. Reduce false positives.
12. Classify severity.
13. Map findings to security standards.
14. Generate remediation recommendations.
15. Generate a professional security report.
16. View previous audits.
17. View vulnerability findings.
18. Track audit progress.
19. Download reports.

## 4. Problem Statement

Application security testing is typically either (a) manual penetration testing —
expensive, slow, expert-dependent — or (b) automated scanner output — fast but noisy,
with high false-positive rates and little developer-oriented context. Developers
need audits that are fast, evidence-based, low in false positives, mapped to
standards and accompanied by actionable remediation.

*Full PPT problem-statement text: PENDING – PPT not provided.*

## 5. Existing System

PENDING – PPT not provided.

(Brief-implied baseline: standalone scanners such as OWASP ZAP and Nuclei produce raw,
unverified alerts; manual testing is required to confirm findings and write reports.)

## 6. Proposed System

A multi-agent pipeline where specialised AI agents orchestrate deterministic security
tools, validate suspected issues with safe evidence, reduce false positives and
produce professional reports. AI is used for reasoning, prioritisation, explanation
and reporting — **not** as the scanner itself.

## 7. Methodology

```
USER → AUTHORIZATION CHECK → TARGET VALIDATION → RECONNAISSANCE
     → VULNERABILITY SCANNING → SAFE VALIDATION
     → VALIDATOR / FALSE-POSITIVE REDUCTION → REPORT GENERATION
     → DATABASE PERSISTENCE → SECURITY REPORT
```

Security Tools → Structured Observations → AI Reasoning → Safe Validation →
Validator → Structured Findings → Report.

## 8. Agent Architecture

| Agent (PPT term) | Responsibility |
|---|---|
| Reconnaissance Agent | Endpoints, API endpoints, technologies, forms, parameters, HTTP metadata, interesting paths → attack-surface inventory |
| Vulnerability Scanner Agent | Runs OWASP ZAP and Nuclei over the attack surface; produces **potential** findings |
| Exploitation Agent | Confirms whether suspected vulnerabilities are real. **Implemented as the controlled Safe Validation Agent** (non-destructive proof only) |
| Validator Agent | Independent evidence review, false-positive reduction, deduplication, normalisation, OWASP/CWE/CVE/CVSS mapping, final status |
| Report Agent | Professional HTML + PDF report with executive summary, findings, evidence, mappings, remediation |

Finding statuses: `confirmed`, `likely`, `suspicious`, `false_positive`, `informational`.

## 9. Technology Requirements

| Layer | Technology |
|---|---|
| Languages | Python, JavaScript / TypeScript |
| Frontend | React.js / Next.js, Tailwind CSS |
| Backend | FastAPI, Pydantic, SQLAlchemy |
| AI / Orchestration | LangChain, LangGraph, configurable LLM provider |
| Security tools | OWASP ZAP, Nuclei |
| Database | PostgreSQL |
| Infrastructure | Docker, Docker Compose |
| Standards | OWASP Top 10, OWASP WSTG (where relevant), CWE, CVE/NVD, CVSS |

## 10. Hardware Requirements

PENDING – PPT not provided.

## 11. Software Requirements

Brief-derived: Python 3, Node.js (Next.js), PostgreSQL, Docker + Docker Compose,
OWASP ZAP, Nuclei, a modern web browser. Exact PPT list: PENDING – PPT not provided.

## 12. Security Standards

- OWASP Top 10 categories for each finding
- OWASP WSTG test references where relevant
- CWE identifiers
- CVE identifiers **only when genuinely applicable** — never invented
  ("Not applicable / no specific CVE identified.")
- CVSS scores **only when reliably determined** ("CVSS not determined.")

## 13. Security & Ethics Boundary

- Authorized testing only; explicit authorization confirmation before active testing,
  stored with user, target, timestamp and scope.
- Default target restrictions: HTTP/HTTPS only; block localhost, loopback, private,
  link-local and cloud-metadata addresses; enforce scope; configurable allowlists.
- No bypass of CAPTCHA, WAF/Cloudflare, authentication, authorization, rate limits or
  other security controls.
- No credential theft, malware, persistence, destructive exploitation, data
  exfiltration, denial of service or privilege escalation.

## 14. Continuous Security Testing

The specification mentions continuous security testing of authorized applications.
Baseline delivery: manual audit initiation, with architecture extensible to
scheduled audits, CI/CD integration and continuous monitoring.

## 15. Expected Deliverables

- Working web application (frontend + backend + agents + tools + database)
- Multi-agent LangGraph pipeline with ZAP and Nuclei integration
- HTML and PDF security reports
- Dashboard, targets, audits, findings, reports, activity, settings UI
- Demo mode (clearly labelled *DEMO / SIMULATED SECURITY AUDIT*)
- Docker Compose deployment (`docker compose up --build`)
- Automated tests
- Academic documentation and UML diagrams

## 16. UML / Architecture Requirements

1. Use Case Diagram
2. Class Diagram
3. Activity Diagram
4. Sequence Diagram
5. System Architecture Diagram
6. Multi-Agent Workflow Diagram
7. Database ER Diagram

Key entities: User, Target, SecurityAudit, ReconnaissanceAgent,
VulnerabilityScannerAgent, ExploitationAgent (implemented as SafeValidationAgent),
ValidatorAgent, ReportAgent, SecurityReport, Vulnerability.

## 17. References

- OWASP Top 10 — https://owasp.org/www-project-top-ten/
- OWASP Web Security Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- MITRE CWE — https://cwe.mitre.org/
- NIST NVD (CVE) — https://nvd.nist.gov/
- FIRST CVSS — https://www.first.org/cvss/
- OWASP ZAP — https://www.zaproxy.org/
- ProjectDiscovery Nuclei — https://github.com/projectdiscovery/nuclei
- LangGraph — https://langchain-ai.github.io/langgraph/

PPT reference list: PENDING – PPT not provided.
