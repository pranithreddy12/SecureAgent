# Feature spec: Context-aware hardening recommendations

Status: **spec, not built** (2026-11-02). Written for the implementing session. The owner will have the
result audited against section 13 after it is built. Record the decision as **ADR-045** when implementing.

Read first, in this order: `PROJECT_MEMORY.md` (sections 3, 19, 21), `backend/app/analysis/recon.py`,
`backend/app/analysis/intent.py`, `backend/app/analysis/scanner.py` (`ScanResult`, `_scan_repo`),
`backend/app/analysis/reporting.py` (`scan_to_report_context`), `backend/app/schemas/report.py`
(`AttackChain`, `ReportContext`), `backend/app/pipeline/stages.py` (`vulnerability_scanner`, `correlation`),
`backend/app/pipeline/report_builder.py`, `backend/app/api/audits.py` (detail endpoint, `attack_chains`).
Attack chains (ADR-012) are the closest existing pattern: an interpretation layer that is **not** a finding.
Copy how chains flow end to end.

---

## 1. What the feature does

Findings answer *"what is broken in this code?"*. Recommendations answer a second question: *"given what
this application is, what data it handles and how many people use it, which protective controls should
it have that we do not see in the code?"*

Inputs:
1. **Code facts** the scanner already extracts: the application model (technologies, request parameters,
   outbound hosts, env vars), routes and guards, dependencies, findings.
2. A few **new code facts** (section 5): detected data categories, detected protective controls.
3. An optional, developer-declared **application profile** (section 4): purpose, expected users, data
   categories, regions, exposure. Code cannot reveal these, so the developer must declare them.

Output: an ordered list of **recommendations**, each with evidence, a rationale, concrete actions, a
reference, and what could not be verified. There is also a list of **observed controls**: protections the
scanner did detect. This credits what is already present and stops it from being recommended again.

## 2. Honesty rules (non-negotiable; each needs a test)

1. **A recommendation is not a finding.** It never appears in `total_findings`, severity counts, risk
   rating, SARIF, baselines, `--fail-on` gating, attack chains, `secureagent fix`, or the findings table. It
   has a `priority` (`recommended` | `consider`) and never a `severity`.
2. **Every recommendation cites its trigger.** `basis` is `code`, `profile` or `code+profile`. Code-based
   triggers must include at least one evidence item (`relpath`, `line` or `null`, `detail`).
3. **Absence is stated as absence of evidence, not as fact.** Write "no rate-limiting library or middleware
   was detected", never "the app has no rate limiting". Every recommendation has a non-empty
   `cannot_verify` naming what static analysis cannot see (gateway, WAF, DB config, cloud settings).
4. **Never infer the profile.** User count, purpose, regions and exposure come only from the declared
   profile. Data categories may be *detected*, but they are reported as `detected` and kept separate from
   `declared`. A rule that needs a profile value does not fire when that value is missing. The output then
   lists the rule under `needs_profile`, so the user knows what declaring it would add.
5. **Compliance is a note, never a verdict.** Allowed wording: "DPDP Act 2023 may apply because...; review
   with whoever owns compliance." Forbidden: any score, percentage, "compliant" or "non-compliant".
6. **Deterministic.** No network, no LLM, no randomness. Output is sorted (priority, then category, then
   id), so the same input gives byte-identical JSON.
7. **No invented references.** Cite only by standard name and chapter, from the list in section 7. Do not
   cite clause or requirement numbers you have not checked.
8. **Secrets stay redacted.** Evidence `detail` never contains a secret value. Reuse the existing
   redaction if a secret finding is referenced.

## 3. Non-goals (do not build)

- Compliance scoring or checklists. An LLM-generated recommendation text in the core path (an optional AI
  rewording may come later, under ADR-017/018 rules; not in this task).
- Inferring user count from code, traffic or anything else.
- New detectors that produce findings. If a rule's signal is really a vulnerability (e.g. client-trusted
  price), it is already a finding. The recommendation may *reference* the finding count but must not
  duplicate it.
- Persisting the profile in the database or a profile-editor UI. The profile lives in the repo's intent
  file. A UI editor is a possible later step.

## 4. The application profile (extends `secureagent-intent.json`)

Add an optional top-level `profile` object. `rules` becomes optional **when** `profile` is present. A file
with neither key is still an error, so the existing error wording is unchanged for that case.

```json
{
  "profile": {
    "purpose": "ecommerce",
    "expected_users": "10k-100k",
    "data_categories": ["pii", "payment"],
    "regions": ["IN", "EU"],
    "exposure": "internet",
    "description": "Marketplace for handmade goods"
  },
  "rules": []
}
```

| Field | Allowed values | Required |
|---|---|---|
| `purpose` | `ecommerce`, `fintech`, `healthcare`, `education`, `social`, `saas`, `internal_tool`, `content`, `government`, `other` | no |
| `expected_users` | `<1k`, `1k-10k`, `10k-100k`, `100k-1m`, `>1m` | no |
| `data_categories` | subset of `pii`, `credentials`, `payment`, `financial`, `health`, `children`, `location`, `biometric`, `government_id` | no |
| `regions` | ISO 3166-1 alpha-2 codes (`IN`, `US`, ...) or `EU` | no |
| `exposure` | `internet`, `internal` | no |
| `description` | free text, max 500 chars, **displayed only, never used by any rule** | no |

Validation: unknown keys or values raise `IntentError` with a message naming the field and the allowed
values. This matches the existing `_parse_rule` style. Load it in `intent.py` as
`load_profile(path) -> Profile | None` (frozen dataclass). Do not change `load_intent`'s return type: it
is used by the pipeline and CLI. Refactor the file read so both functions share it, and keep every
existing `test_business_logic.py` / intent test passing unchanged.

Also update `backend/app/demo/demo_fixtures/vulnerable_shop/secureagent-intent.json` with a realistic
profile, so `secureagent demo` shows the feature.

## 5. New code signals (small, in `recon.py`)

Keep these additions inside `ApplicationModel` so the pipeline's `_recon_sync` gets them automatically.

### 5.1 Protective-control technologies
Extend `_TECH` with the entries below. A control is "observed" when its module is imported or listed as a
dependency.

| Control | Modules (Python / JS) |
|---|---|
| Rate limiting | `slowapi`, `flask_limiter`, `django_ratelimit`, `express-rate-limit`, `rate-limiter-flexible`, `@nestjs/throttler` |
| Security headers | `flask_talisman`, `secure`, `helmet` (exists), `django-csp` / `csp` |
| MFA / OTP | `pyotp`, `django_otp`, `otplib`, `speakeasy` |
| Password hashing | `bcrypt` (exists), `argon2` (exists), `passlib` |
| CSRF | `flask_wtf`, `csurf` |
| Payments | `stripe`, `razorpay`, `paypalrestsdk`, `braintree` |
| File upload | `multer`, `python-multipart` / `multipart` |
| Error monitoring | `sentry_sdk`, `@sentry/node` |
| Encryption | `cryptography`, `nacl` |

Add a `controls: set[str]` to the model (control names from the left column), filled alongside
`technologies`. Include it in `summary()` as `"controls"`. Check `AuditDetail.application_model:
dict[str, list[str]]`: it accepts a new key without a schema change, but verify that.

Django's built-in CSRF middleware and FastAPI/Express built-ins are **not** import-detectable. The
existing misconfig detector already reports *disabled* CSRF, so do not claim "CSRF missing" from
imports alone (section 6, rule HR-CSRF is deliberately absent).

### 5.2 Data-category detection
A vocabulary match on (a) the `parameters` already collected, and (b) field names declared in Python
models: a regex over lines like `name = Column(`, `name: Mapped[`, `name = mapped_column(`,
`name = models.XField(`, and Pydantic `name: str` inside a class that subclasses `BaseModel`. Keep it
regex-based and per line, like the rest of `recon.py`. Do not write an AST pass for this.

| Category | Word-matched names (match whole words of snake/camel-split identifiers, like the secrets scanner) |
|---|---|
| `pii` | email, phone, mobile, address, dob, birth, birthdate, first_name, last_name, full_name, gender |
| `credentials` | password, passwd, pin, otp, secret_answer |
| `payment` | card_number, cardnumber, pan, cvv, cvc, expiry, iban, upi, upi_id |
| `financial` | salary, income, account_number, balance, ifsc |
| `health` | diagnosis, prescription, blood_group, medical, allergy, insurance_id |
| `government_id` | aadhaar, pan_number, ssn, passport, national_id, voter_id |
| `location` | latitude, longitude, lat, lng, geolocation |
| `children` | (no reliable code signal: profile-only) |
| `biometric` | fingerprint_template, face_encoding, biometric |

Note: `pan` is ambiguous (card PAN vs. Indian PAN number). Only count `pan` inside `payment` when a
payment technology or another payment word is present in the same file. Write a test for both cases.

Store as `data_fields: dict[str, set[tuple[str, int, str]]]` (category -> {(relpath, line, name)}),
capped at 20 per category. `summary()` gets `"data_categories": sorted(keys)`.

### 5.3 Signals derived from existing data (no new parsing)
Compute these in the new module, not in `recon.py`:
- `login_routes`: routes whose path matches `(login|signin|sign-in|token|auth/|session)`.
- `upload_routes`: routes with a `file:` parameter in the same file, or path containing `upload`.
- `admin_routes`: path contains `/admin`.
- `state_changing_routes`: method in POST/PUT/PATCH/DELETE.
- `user_url_params`: parameters named `url`, `uri`, `callback`, `webhook`, `redirect`, `next`, `target`.
- Finding counts by type (from `ScanResult`), used only to *reference* findings, e.g. "3 open findings of
  type `missing_function_level_authorization`".

## 6. Rules (first version: these 16; nothing else)

Each rule is one small function `(signals, profile) -> Recommendation | None` in a tuple `RULES`. Rule IDs
are stable (`HR-` + short name), because users may refer to them later.

| ID | Fires when | Priority | Category | Actions (summary) | Reference |
|---|---|---|---|---|---|
| HR-RATELIMIT-LOGIN | `login_routes` non-empty and no rate-limiting control | recommended | authentication | throttle by account and IP; progressive delay / lockout; generic error messages | OWASP ASVS V2; OWASP Authentication Cheat Sheet |
| HR-RATELIMIT-API | profile `exposure=internet` and `expected_users` >= `10k-100k` and no rate-limiting control | recommended | abuse_prevention | per-client API limits; quotas; gateway or WAF limits | OWASP API Security Top 10 (API4) |
| HR-MFA | login routes present and (`admin_routes` non-empty or profile purpose in fintech/healthcare/government) and no MFA control | recommended | authentication | TOTP/WebAuthn for admins first, then optional for users | OWASP ASVS V2 |
| HR-PASSWORD-HASH | `credentials` category detected and no password-hashing control | recommended | authentication | Argon2id or bcrypt; never reversible encryption | OWASP Password Storage Cheat Sheet |
| HR-PII-ENCRYPT | `pii`, `health`, `government_id` or `financial` detected or declared | recommended | data_protection | encrypt sensitive columns at rest; restrict who can read them; mask in UI and logs | OWASP ASVS V8, V6 |
| HR-PII-MINIMISE | any sensitive category detected or declared | consider | data_protection | collect only what is needed; retention period and deletion job; export/delete-my-data path | OWASP ASVS V8 |
| HR-PAYMENT-SCOPE | `payment` detected or declared, or a payment control present | recommended | payments | use the provider's hosted fields / tokenization; never store card number or CVV; webhooks verified by signature | PCI DSS (scope reduction) |
| HR-PAYMENT-SERVER-PRICE | purpose `ecommerce`/`fintech` or a payment control present | recommended | payments | compute amounts server-side; idempotency keys on charge endpoints. Reference the existing `client_trusted_value` finding count if > 0 | OWASP Business Logic (ASVS V11) |
| HR-UPLOAD | `upload_routes` non-empty | recommended | file_handling | size and type limits by content, not extension; store outside web root with random names; malware scan if users share files | OWASP File Upload Cheat Sheet; ASVS V12 |
| HR-HEADERS | a web framework is detected and no security-headers control | consider | transport_headers | CSP, HSTS, X-Content-Type-Options, frame-ancestors; may be set by a proxy (say so in `cannot_verify`) | OWASP Secure Headers Project; ASVS V14 |
| HR-SSRF-EGRESS | `user_url_params` non-empty and outbound HTTP technology present | recommended | abuse_prevention | allow-list outbound hosts; block private/metadata IPs; no redirects to internal hosts | OWASP SSRF Prevention Cheat Sheet |
| HR-AUDIT-LOG | `admin_routes` or (`state_changing_routes` and sensitive data) present | consider | logging_monitoring | append-only audit log of who changed what; alert on admin actions; do not log sensitive values | OWASP ASVS V7; OWASP Top 10 A09 |
| HR-MONITORING | profile `expected_users` >= `10k-100k` and no error-monitoring control | consider | logging_monitoring | error tracking, uptime checks, alerting with an owner | OWASP Top 10 A09 |
| HR-DEPENDENCY-PIPELINE | dependencies found and no lockfile for an ecosystem that has a manifest, or any dependency finding exists | consider | supply_chain | lock versions; scheduled dependency updates; run `secureagent` in CI (point to `action.yml`) | OWASP Top 10 A06 |
| HR-AUTHZ-REVIEW | > 0 findings of types `idor`, `missing_function_level_authorization` or `inconsistent_authorization`, and profile `expected_users` declared | recommended | authentication | central authorization policy; deny by default; per-object ownership checks. Reference the finding counts | OWASP ASVS V4; API Security Top 10 (API1) |
| HR-COMPLIANCE-NOTE | profile `regions` and data categories (detected or declared) intersect the table below | consider | compliance_note | "may apply" note per regime + a pointer to consult; never a verdict | names only, per table |

Compliance-note table (names only; wording "may apply"):

| Condition | Regime |
|---|---|
| region `IN` and any personal data | Digital Personal Data Protection Act, 2023 (India) |
| region `EU` and any personal data | GDPR |
| region `US` and `health` | HIPAA (if the operator is a covered entity or business associate) |
| region `US` and `children` | COPPA |
| `payment` anywhere | PCI DSS |

Escalation by scale: when `expected_users` is `100k-1m` or `>1m`, upgrade `consider` to `recommended` for
HR-HEADERS, HR-AUDIT-LOG and HR-MONITORING, and add a sentence to `rationale` saying why. Do nothing else
with the user count. Never upgrade on a guess.

`needs_profile`: list the IDs of rules that did not fire *only* because a profile field was missing (e.g.
HR-RATELIMIT-API with no `expected_users`), each with the missing field names.

## 7. Allowed references

Use only these names, at chapter level: OWASP Top 10 (2021) category codes A01-A10; OWASP API Security Top
10 (2023) API1-API10; OWASP ASVS 4.0 chapters V1-V14 by number and name; the OWASP Cheat Sheet Series by
sheet title; PCI DSS; GDPR; Digital Personal Data Protection Act, 2023; HIPAA; COPPA. If a rule seems to
need a reference that is not on this list, leave the reference empty and flag it in the ADR.

## 8. Data shapes

Add to `backend/app/schemas/report.py` (pydantic only, so the CLI stays dependency-light per ADR-009):

```python
class RecommendationEvidence(BaseModel):
    location: str          # "relpath:line" or "relpath" or "profile"
    detail: str            # e.g. "parameter json:card_number", "route POST /login"

class Recommendation(BaseModel):
    id: str                # "HR-UPLOAD"
    title: str
    category: str          # one of the categories used in section 6
    priority: Literal["recommended", "consider"]
    basis: Literal["code", "profile", "code+profile"]
    rationale: str
    actions: list[str]     # 2-4 short imperative items
    evidence: list[RecommendationEvidence] = []   # max 5
    references: list[str] = []
    cannot_verify: str     # non-empty
    related_findings: dict[str, int] = {}         # finding type -> count

class HardeningSummary(BaseModel):
    profile_declared: dict[str, Any] = {}         # as declared; {} when absent
    data_categories_detected: list[str] = []
    observed_controls: list[str] = []
    recommendations: list[Recommendation] = []
    needs_profile: list[dict[str, Any]] = []      # {"id": ..., "missing": [...]}
```

`ReportContext` and `AuditDetail` each gain `hardening: HardeningSummary | None = None`.

## 9. Module layout

- **New:** `backend/app/analysis/hardening.py`: `collect_signals(result, profile)`,
  `RULES`, `recommend(result, profile) -> HardeningSummary`. Pure functions, no I/O. Target size: under
  about 350 lines. If it grows past that, the rules are too clever.
- `scanner.py`: `ScanResult` gains `profile` and `hardening`. `_scan_repo` loads the profile next to the
  intent rules and calls `recommend()` **after** findings are final, i.e. after inline ignores and
  suppressions. Recommendations must reflect the reported findings, not the raw ones. `total_findings`
  is untouched.
- `reporting.py`: copy `result.hardening` into the `ReportContext`.

## 10. Integration points

| Surface | Change |
|---|---|
| CLI text | new flag `--recommend` prints a "Hardening recommendations" block (like `--recon`/`--matrix`). Default text output unchanged |
| CLI JSON | always include `"hardening": {...}` |
| SARIF | **unchanged**. Add a test proving no recommendation appears |
| Baseline / `--fail-on` | **unchanged**. Add a test: a repo whose only change is a new recommendation does not fail the gate |
| HTML/PDF report | new **section 20 "Hardening Recommendations"** placed after section 19 (avoid renumbering 1-19). Add it to the table of contents. Show profile (or "no profile declared; N rules need one" + the field list), observed controls, then each recommendation with priority label, basis, evidence, actions, references and "Could not verify". Style it with the existing tokens; no severity colours |
| Executive summary | one line only: "N hardening recommendations (see section 20)". Do not mix them into risk rating |
| Pipeline (`stages.py`) | in `vulnerability_scanner`, store `state["hardening"] = result.hardening.model_dump(mode="json")` on `audit.stage_state` (same pattern as `correlation` storing chains). Resume-from-failed-stage must still work: add a test |
| `report_builder.py` | read `state.get("hardening")` into the context |
| API | `GET /api/audits/{id}` detail returns `hardening` from `stage_state` (mirror `attack_chains` in `api/audits.py`). No new endpoint |
| Frontend | `frontend/app/(app)/audits/[id]/page.tsx`: a "Hardening recommendations" `Card` below attack chains, using existing `components/ui.tsx` primitives. Each item collapsible; priority shown as text label, not a severity badge. Show "Declare an application profile in secureagent-intent.json to get N more" when `needs_profile` is non-empty. Add the type in `frontend/types/` |
| MCP | new tool `hardening_recommendations` (args: `path`, optional `intent`) returning `HardeningSummary` JSON. Read-only, same input validation as `application_model` |
| Demo | `secureagent demo` shows at least 5 recommendations from the demo fixture's profile |

Read `frontend/node_modules/next/dist/docs/` before touching frontend code (Next 16; see PROJECT_MEMORY section 9).

## 11. Tests (backend: new `tests/test_hardening.py`, plus small additions)

Snippet-based, like `test_business_logic.py`. Minimum set:

1. Profile parsing: valid profile; profile-only file (no `rules`); unknown field; unknown enum value;
   description over 500 chars; neither key -> existing error.
2. Each of the 16 rules: one positive case and one negative case (the control present, or the profile
   field absent).
3. `needs_profile` lists HR-RATELIMIT-API with `["expected_users", "exposure"]` when no profile exists.
4. Scale escalation changes priority for exactly the three named rules.
5. `pan` disambiguation (payment vs. government ID).
6. Every recommendation has non-empty `cannot_verify`. Every `code`/`code+profile` one has >= 1 evidence
   item. No `severity` attribute exists (schema test).
7. Determinism: two runs give identical JSON.
8. Isolation: `total_findings`, SARIF output and the baseline gate are identical with and without a profile.
9. Inline-ignored / suppressed findings do not count in `related_findings`.
10. No secret value appears in any recommendation (reuse the demo's secret).
11. Compliance notes: wording contains "may apply". No output contains "compliant" or "%"
    (string-scan test over the whole `HardeningSummary` JSON).
12. CLI: `--recommend` text block; JSON key present; `test_cli_standalone.py` still passes (no new imports
    of the web stack).
13. Pipeline: `stage_state["hardening"]` written; report section rendered; audit detail API returns it;
    resume still works.
14. MCP tool: happy path + bad path argument.
15. Demo: >= 5 recommendations.

Frontend: one Vitest test for the card (renders items, the `needs_profile` hint, and nothing when
`hardening` is null). The Playwright suite does not need extending.

Run before finishing: full backend suite, `ruff check` + `ruff format --check` **scoped to the files you
touched**, frontend `npm run lint`, `npm run typecheck`, `npx vitest run`, and `secureagent benchmark` (it
must be unchanged: this feature adds no findings).

## 12. Documentation to update

- `docs/adr/ADR-045-hardening-recommendations.md`: context, decision, the honesty rules, what is not
  built, alternatives (LLM-generated advice; compliance scoring), both rejected and why.
- `docs/static-analysis.md`: a short section linking here.
- `docs/OVERVIEW.md`: one row in sections 2 and 3, ADR row in section 9.
- `docs/mcp.md`: the new tool.
- `README.md`: one line and an example of the `profile` block.
- `PROJECT_MEMORY.md`: section 3 (implemented), section 14 (ADR-045), section 19 (limits), section 22
  (session summary).
- `PROJECT_CHANGELOG.md`: entry.
- `docs/paper/PROJECT_DOCUMENTATION.md`: add contribution 9 and a section 6 subsection. Write the
  evaluation status as "not evaluated", and do not invent an evaluation.

## 13. Acceptance checklist (what the audit will check)

- [ ] Every honesty rule in section 2 has a test that would fail if the rule broke.
- [ ] No recommendation path touches severity, `total_findings`, SARIF, baselines, gating or chains.
- [ ] No profile value is inferred. Detected and declared data categories are kept separate.
- [ ] Exactly the 16 rules in section 6. IDs, triggers and references match the tables. No extra rules.
- [ ] References use only section 7 names. No invented clause numbers.
- [ ] `cannot_verify` is specific per rule, not a single generic sentence copied 16 times.
- [ ] Output deterministic and sorted.
- [ ] CLI stays dependency-light (`test_cli_standalone.py` green).
- [ ] Benchmark numbers unchanged. Full test suite green. Counts recorded in PROJECT_MEMORY.
- [ ] Regex changes: grep `app/` and `tests/` for a literal backspace (`\x08`) after any scripted edit
      (PROJECT_MEMORY section 21: shell heredocs have corrupted `\b` in regexes before). Write regex code
      with the file tools, not heredocs.
- [ ] Docs in section 12 updated. No numbers in docs that were not measured.
- [ ] Commits: explicit paths only (never `git add -A`). **No `Co-Authored-By` / AI attribution trailers**
      (owner rule for this repo).

## 14. Evaluation for the paper (later; do not claim before it is run)

Plan, not result: run on 5-10 projects with a declared profile, then have two reviewers rate each
recommendation `relevant` / `not relevant` / `already present (missed control)`. Report the relevant-rate
per rule and the missed-control rate (a direct measure of the "absence of evidence" problem). Record it in
`docs/evaluation.md`. Until then, the paper describes this as a feature with **no** measured usefulness.
