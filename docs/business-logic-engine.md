# SecureAgent – Business-Logic Vulnerability Engine (Design)

Status: **Design (2026-10-03)**. Implements the grey-box capability decided in
ADR-008. This is a scope change over the original black-box baseline; see
`PROJECT_MEMORY.md` §15. No code yet — this document specifies it.

> Purpose: help the developers of an application find the **logic flaws** that
> pattern-based scanners miss — the ones that get real apps breached — and give
> them the evidence and the fix. Defensive, authorized use only.

---

## 1. Why logic flaws need more than a scanner

A scanner asks "does this response match a known-bad pattern?". A logic flaw is
different: the response is perfectly well-formed, but the application allowed
something it should not have. Deciding "should not have" requires knowing the
application's **intended rules**. SecureAgent learns those rules from two places
the developer already has:

1. **The source code** — what authorization, ownership, ordering and validation
   the app *actually* implements.
2. **A short description** — the roles, the sensitive workflows, what each role is
   and isn't allowed to do, and (optionally) test accounts.

It then compares intended behaviour against the live application and the code, and
reports where a rule looks unenforced — with the code location and non-destructive
evidence, plus remediation.

## 2. Inputs

| Input | Source | Required | Notes |
|---|---|---|---|
| Target URL + scope | existing (Target) | yes | authorized, scope-checked |
| Source repository | git URL or uploaded archive | recommended | user confirms authorization; read-only |
| Developer description | structured form | optional | roles, workflows, sensitive actions, test accounts |
| Dynamic recon | existing agent | yes | endpoints, forms, params, tech |

All inputs are gated by the single authorization confirmation, now worded to cover
both the target **and** its source code.

## 3. The Application Model (central artifact)

A deterministic, structured representation built by the Code Intelligence agent
(from AST facts) and enriched by recon. The reasoning agent consumes this; the LLM
never invents its fields.

```
ApplicationModel:
  languages:        [{language, file_count}]
  frameworks:       [{name, confidence, evidence_path}]
  routes:           [Route]
  data_models:      [Entity]           # tables/models and their ownership fields
  roles:            [role_name]        # from code + developer description
  workflows:        [Workflow]         # ordered steps, from description/code
  trust_boundaries: [TrustBoundary]    # where external input enters a handler
  secrets:          [SecretFinding]    # hardcoded creds/keys (redacted)

Route:
  method, path, handler_ref (file:symbol)
  auth_guards:        [guard]          # decorators/middleware/checks detected
  authorization:      none|role|ownership|unknown
  reads_request_fields:[field]         # body/query fields the handler consumes
  writes_entities:    [entity]
  maps_to_live_endpoint: url|null      # correlation with dynamic recon

Workflow:
  name, steps:[{name, route_ref, requires_prior:[step]}]
```

Correlation is what creates signal: a `Route` with `authorization: none` that the
developer marked admin-only, that recon also found reachable, is a high-confidence
access-control candidate.

## 4. Logic-flaw categories (what it reasons about)

Described at the level of *what is detected* and *why it matters to the developer*.
Each maps to OWASP (Top 10 and WSTG) and CWE.

| Category | What SecureAgent looks for | Standard |
|---|---|---|
| Broken object-level access (BOLA/IDOR) | A handler fetches a record by an id from the request without checking the record belongs to the caller | OWASP A01 / CWE-639 / WSTG-ATHZ-04 |
| Broken function-level access | An endpoint whose code has no role/authorization guard but performs a privileged action | OWASP A01 / CWE-285 / WSTG-ATHZ-02 |
| Inconsistent authorization | The same entity is protected on one route but reachable unprotected via another | OWASP A01 / CWE-285 |
| Workflow / sequence bypass | A step reachable without evidence the required prior step completed | OWASP A04 / CWE-840 / WSTG-BUSL-06 |
| Client-trusted values | Server uses a price, total, quantity, role or flag taken from the request instead of recomputing/looking it up | OWASP A04 / CWE-602 / WSTG-BUSL-01 |
| Missing limits / abuse | An action that should be rate-limited, quantity-capped or one-time-use with no such control in code | OWASP A04 / CWE-770 / WSTG-BUSL-05 |
| Hardcoded secrets | Credentials, API keys or tokens committed in source | OWASP A05/A07 / CWE-798 |
| Insecure direct state change | State transition performed without validating the current state or the actor's right to it | OWASP A04 / CWE-840 |

This list is extensible; each category is a small, testable analyser plus a reasoning
prompt, not one monolithic "find bugs" call.

## 5. Agents

### 5.1 Code Intelligence Agent (new, static)
- Ingests the repo via `repo_tool` (git clone of an authorized URL, or uploaded
  archive), enforcing size/file-count/type limits and ignoring vendored deps.
- Parses with tree-sitter (language-aware). Extracts routes, guards, data models,
  request-field usage, and candidate state transitions **deterministically**.
- Detects frameworks to know where routes/guards live.
- Emits the `ApplicationModel` and a list of `SecretFinding`s (values redacted).
- **Never executes** anything from the repo.

### 5.2 Business-Logic Reasoning Agent (new)
- Input: `ApplicationModel` + developer description + dynamic recon. All structured.
- For each category, produces `LogicFindingCandidate`s with: the rule it believes
  applies, the code evidence (file:line) that suggests the rule is unenforced, a
  confidence prior, and a **safe evidence plan** (what non-destructive observation
  would corroborate it).
- Pydantic-validated output; cannot set final status or invent CWE/CVE.

### 5.3 Safe Validation Agent (existing, ADR-003)
- Executes the safe evidence plan against the authorized target: observational,
  non-destructive corroboration only. Many logic flaws will remain unproven and
  that is reported honestly.

### 5.4 Validator + Report (existing)
- Merge code-evidence and dynamic-evidence, dedupe, assign status
  (`confirmed`/`likely`/`suspicious`/`false_positive`/`informational`) with a
  reason, map standards, and render the report. A logic finding confirmed only by
  code (not safely reproducible live) is capped at `likely` with the code evidence.

## 6. Updated workflow (LangGraph)

```
START
 → Authorization (target + source)
 → Target & Source Validation
 → fan-out:
      ├─ Dynamic Reconnaissance
      └─ Code Intelligence (static)
 → Build Application Model (merge)
 → fan-out:
      ├─ Vulnerability Scanning (ZAP/Nuclei)      → suspected (pattern) findings
      └─ Business-Logic Reasoning                 → suspected (logic) findings
 → Safe Validation (both kinds)
 → Validator (false-positive reduction, status)
 → Report → Persist → END
```

Code Intelligence and Reasoning are **non-fatal**: if no source is provided, those
branches are skipped and the audit runs black-box, with the report noting that
source analysis was not performed.

## 7. Data model additions (design)

Beyond the eight tables in `docs/database.md`:

- `source_artifacts` — one per audit source: kind (git/archive), reference
  (redacted), commit/hash, size, file_count, status.
- `application_models` — one per audit: the serialized `ApplicationModel` (JSONB,
  size-capped), languages, frameworks.
- Reuse `vulnerabilities` for logic findings, adding columns: `code_locations`
  (JSONB: file/line refs), `detection_source` (`dynamic`|`static`|`correlated`).
- Secrets are stored as `vulnerabilities` of type `hardcoded_secret` with the value
  **redacted** (store a fingerprint + masked preview, never the secret).

## 8. Safety & scope boundaries (in addition to the existing security model)

- The user confirms authorization for the **source** as well as the target.
- Repo ingestion limits: max archive size, max files, max file size, type
  allowlist (text/source only), path traversal rejected, symlinks ignored,
  `.git` history not mined for secrets beyond the checked-out tree (configurable).
- No code from the repo is executed, imported, or installed.
- Secrets: redact on capture (store masked preview + salted fingerprint); never log
  or transmit the full value; the finding tells the developer where it is so they
  can rotate and remove it.
- Dynamic corroboration remains authorized, scope-checked, rate-limited and
  non-destructive (ADR-003). SecureAgent never implements control bypass or
  destructive actions.
- An uploaded repo is the user's data: access-controlled like every other resource,
  deletable, and excluded from version control / backups of SecureAgent itself.

## 9. Technology additions (expected)

- **tree-sitter** (+ grammars) for language-aware parsing. Start with the stacks
  most of the target audience uses; add grammars incrementally.
- **git** (authorized clone) and safe archive extraction for ingestion.
- No new datastore; JSONB in PostgreSQL holds the model.

Recorded as a decision in ADR-008; exact library pins chosen at implementation.

## 10. Phasing (fits the existing roadmap)

These extend — they do not replace — Phases 6–13. Target/authorization (Phases
4–5) remain a prerequisite.

- **BL-1** Source ingestion tool + `source_artifacts` (limits, authorization).
- **BL-2** Code Intelligence: framework/route/guard extraction for the first stack;
  `ApplicationModel`.
- **BL-3** Hardcoded-secret detection (self-contained, high value, easy to demo).
- **BL-4** Business-Logic Reasoning agent + candidate schema.
- **BL-5** Wire into Safe Validation + Validator + Report (logic findings in report).
- **BL-6** Second language/stack; correlation with dynamic recon.
- **BL-7** Demo fixtures: an intentionally flawed sample app showing a confirmed
  access-control finding and a code-evidenced workflow finding, clearly labelled.

## 11. Honesty commitments (unchanged, restated for logic flaws)

- A logic finding is only `confirmed` when non-destructive evidence against the
  authorized target supports it; otherwise `likely`/`suspicious` with the code
  reasoning shown.
- No invented CVE/CVSS (logic flaws usually have neither — the report says so).
- Demo results are always labelled **DEMO / SIMULATED SECURITY AUDIT**.
- Severity reflects real impact, never inflated to impress.
