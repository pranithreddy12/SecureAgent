# SecureAgent – Agent & LangGraph Workflow Design

Status: **Design (Phase 0)**.

## 1. Shared State (`AuditState`)

A `TypedDict` used by LangGraph; every field is JSON-serialisable so it can be
persisted per stage.

| Field | Type | Notes |
|---|---|---|
| audit_id, user_id, target_id | str (UUID) | |
| target_url | str | Normalised URL |
| authorization_status | bool | From latest `AuthorizationRecord` |
| target_scope | `TargetScope` | allowed hosts, path prefixes |
| demo_mode | bool | Selects simulated tool adapters |
| reconnaissance_results | `ReconResult` | |
| technologies, endpoints | list | Copied from recon for convenience |
| scanner_results | list[`RawToolAlert`] | Truncated raw ZAP/Nuclei records |
| suspected_findings | list[`SuspectedFinding`] | Normalised potential findings |
| validation_results | list[`ValidationResult`] | |
| rejected_findings | list[`FinalFinding`] | status = false_positive |
| final_findings | list[`FinalFinding`] | |
| report | `ReportMeta` | |
| current_stage | Stage enum | |
| progress | int 0–100 | |
| errors | list[`StageError`] | Non-fatal agent errors |
| timestamps | dict[stage, {started, completed}] | |

## 2. Graph

```
START
  → authorization_check      (fail → END, audit failed)
  → target_validation        (fail → END, audit failed)
  → reconnaissance
  → attack_surface_processing
  → vulnerability_scanning
  → [has suspected findings?]
        ├─ no  → report_generation
        └─ yes → safe_validation → validator → report_generation
  → persist_results
  → END
```

Stage → progress: authorization 5, target_validation 10, reconnaissance 30,
attack_surface 35, scanning 60, safe_validation 75, validator 85, report 95,
persist 100.

## 3. Failure & Resumability

- Gate nodes (authorization, target validation) are **fatal**: the audit fails and no
  traffic is sent to the target.
- Tool/agent nodes are **non-fatal where possible**: e.g. ZAP unavailable → Nuclei and
  passive-check results are still used; the error is stored in `state.errors` and
  `AuditLog`, and the report lists it under Limitations.
- After each node the runner persists `current_stage`, `progress` and that stage's
  output in one DB transaction.
- Retry: `POST /api/audits/{id}/start` on a `failed` audit resumes from the first
  stage without a completed timestamp, rebuilding state from persisted rows. Gate
  nodes always re-run on resume (authorization may have been revoked).
- Idempotency: finding fingerprint = sha256(audit_id, normalised type, endpoint,
  parameter) with unique constraint `(audit_id, fingerprint)`, so retries upsert
  instead of duplicating.

## 4. Agents

All agents expose `async def run(state) -> partial state`, use Pydantic I/O, and log
every action to `AuditLog` with an `[AUDIT-<short id>]` prefix.

### 4.1 ReconnaissanceAgent
Tools: `recon_tool` — a bounded crawler (same-scope links only, forms, parameters,
response headers, `robots.txt`, `sitemap.xml`, technology fingerprinting from
headers/HTML/cookies, well-known API description paths such as `/openapi.json`).
Optional ZAP spider. Limits (max pages, depth, request rate, total timeout) come
from settings.
Output: `ReconResult` (target, technologies, endpoints, api_endpoints, forms,
parameters, headers, interesting_paths).

### 4.2 VulnerabilityScannerAgent
Tools:
- `zap_tool` — ZAP context restricted to the scope regex; spider, passive scan, and
  active scan with a conservative, non-destructive policy; alerts fetched as JSON.
- `nuclei_tool` — argv-list subprocess (never a shell), JSONL output, rate-limited,
  intrusive / DoS template tags excluded, output size capped.
- Deterministic passive checks on recon data (security headers, cookie flags, CORS,
  information disclosure in headers).

Output: `SuspectedFinding[]` — always *potential*, never confirmed by this agent.

### 4.3 SafeValidationAgent (PPT: "Exploitation Agent")
The controlled, non-destructive implementation of the PPT's exploitation stage. It
re-observes the target to gather **evidence**, never to cause impact. All requests
go through `validation_tool`, which enforces scope, authorization, rate limit,
timeout and response-size caps.

Validation strategies (selected by normalised finding type):

| Category | Evidence gathered |
|---|---|
| Reflection-type issues (e.g. reflected XSS) | Send a unique, inert alphanumeric marker; check whether and in what context (HTML body / attribute / script) it is reflected unencoded |
| Configuration issues (headers, cookies, CORS, TLS-related headers) | Re-fetch and re-check the specific header/flag |
| Exposed files / information disclosure | Re-fetch the path; confirm status code and a content signature; store only a short, redacted excerpt |
| Injection indicators (e.g. SQL error messages) | Compare a baseline response with the scanner's recorded response for known error signatures; no data retrieval |
| Outdated components | Re-confirm the version banner; CVE comes only from tool/template metadata |
| Anything else | Not actively re-tested; marked `validated: null` with reason "no safe validation strategy" |

Never: state-changing methods beyond a single benign form submission of the marker,
authentication bypass attempts, data extraction, persistence, high-volume requests.

Output: `ValidationResult` (finding_id, validated: true/false/null, confidence,
evidence, validation_method, risk_notes).

### 4.4 ValidatorAgent
Deterministic rules first, optional LLM notes second:

1. Deduplicate by fingerprint; merge sources (ZAP + Nuclei agreement raises
   confidence).
2. Normalise type → OWASP Top 10 category + CWE via a static mapping table.
3. Status:
   - `confirmed` — validation positive with direct evidence
   - `likely` — validation inconclusive, multiple sources or high tool confidence
   - `suspicious` — single low-confidence source, no validation
   - `false_positive` — validation negative (evidence contradicts the alert)
   - `informational` — no security impact on its own
4. Severity: tool severity, adjusted only by documented rules (e.g. a
   false-positive has no severity weight). Never inflated.
5. CVE / CVSS only if provided by tool metadata; otherwise
   "Not applicable / no specific CVE identified." / "CVSS not determined."
6. LLM (optional) adds explanation, impact and remediation wording; its output is
   schema-validated and cannot change status or identifiers.

Every final finding carries a `status_reason` explaining the decision.

### 4.5 ReportAgent
Builds the report context from persisted data and renders Jinja2 → HTML → PDF.
Sections: Executive Summary, Target Information, Audit Information, Authorization
Information, Methodology, Attack Surface Summary, Technology Stack Detected,
Findings Summary, Severity Distribution, Detailed Findings, Evidence, OWASP / CWE /
CVE / CVSS mapping, Remediation, Validation Status, Limitations, Audit Timeline.
Demo audits carry a **DEMO / SIMULATED SECURITY AUDIT** watermark/banner on every page.

## 5. Demo Mode

When `DEMO_MODE=true` (or an audit is explicitly created in demo mode), tool adapters
are replaced with fixture-backed adapters reading `backend/app/demo/fixtures/*.json`.
The whole graph, validator, persistence and reporting run for real on that data.
No network traffic is sent. Audits are flagged `is_demo=true` in the database and
labelled in every UI view and report.
