# ADR-045: Context-aware hardening recommendations

- **Date:** 2026-11-02
- **Status:** Accepted (spec: `docs/feature-hardening-recommendations.md`)

## Context

Findings answer "what is broken in this code?". They cannot answer "given what this application is,
which protective controls should it have that we do not see?" (rate limiting on login, MFA for admins,
payment-scope reduction, upload limits, ...). Code cannot reveal purpose, user count, regions or
exposure, so those must be declared by the developer.

## Decision

Add a recommendations layer, modelled on attack chains (ADR-012): an interpretation layer that is
**not** a finding.

- `backend/app/analysis/hardening.py`: 16 fixed rules (`HR-...`), pure functions over a finished
  `ScanResult` and an optional `Profile`. No network, no LLM, deterministic and sorted.
- `secureagent-intent.json` gains an optional `profile` object (`rules` becomes optional when it is
  present). `load_profile()` validates strictly; `load_intent()` is unchanged for callers.
- `recon.py` gains protective-control detection (import/dependency based), data-category detection
  (field and parameter names) and a few evidence sites (upload files, user-supplied URL parameters).
- Output: `HardeningSummary` on `ScanResult`, `ReportContext`, CLI JSON (`hardening`), `--recommend`,
  report section 20, `stage_state["hardening"]`, `GET /api/audits/{id}`, the audit page, and MCP
  `hardening_recommendations`.

### Honesty rules (each has a test)

1. Never a finding: no severity, not in totals, SARIF, baselines, `--fail-on`, chains or fixes.
2. Every item cites its trigger (`basis`) and, for code-based ones, evidence.
3. Absence is "no X was detected", and every item has a rule-specific `cannot_verify`.
4. The profile is never inferred; detected and declared data categories are kept separate; a rule that
   needs a missing profile field does not fire and is listed under `needs_profile`.
5. Compliance is a "may apply" note, never a verdict, score or percentage.
6. Deterministic output. 7. References only from the allowed list. 8. No secret values.

## Deviations and judgement calls

- The spec asks for `tests/test_hardening.py`; that file already exists (login throttling), so the tests
  are in `tests/test_hardening_recommendations.py`.
- **Reference left out:** HR-HEADERS lists "OWASP Secure Headers Project" in spec section 6, but section 7
  does not allow it. Only ASVS V14 Configuration is cited.
- Suppressed findings (justified suppressions) are applied when the report context is built, so
  `scan_to_report_context` recomputes the recommendations excluding them; `ScanResult.hardening` itself
  already excludes inline-ignored findings.
- HR-HEADERS needs at least one detected route to have evidence; with a framework but no routes it stays
  quiet.
- The `payments` / `file_upload` / `encryption` / `error_monitoring` "controls" are observed technologies,
  not proof that a control is correctly used.
- A lone `pan` name counts as `payment` only when a payment SDK is imported in the same file or another
  payment word is present; `pan_number` is `government_id`.
- `HR-DEPENDENCY-PIPELINE` treats a `requirements*.txt` as a pinned list (no lockfile warning).

## Audit corrections (2026-11-02)

An audit of the first build found three name-based false triggers, each now a regression test in
`tests/test_hardening_recommendations.py`:

- `token_expiry` matched the payment word `expiry`, so any JWT app got HR-PAYMENT-SCOPE and a PCI DSS note.
  `expiry` now counts only with payment context (like `pan`); `card_expiry` is an explicit payment name.
- `pin_code` (an Indian postal code) matched `pin` and triggered HR-PASSWORD-HASH. `pin` followed by
  `code` is ignored.
- Models in test/fixture files fed the data categories. Data detection now skips the paths the
  `test_or_example_code` validation rule covers (`validation.is_test_path`).

Known minor gaps, not fixed: the report table of contents links section 20 even when no hardening data
exists; owner triage in the web app does not recompute `related_findings`; suppression exclusion is
unit-tested through `recommend()` but not end to end through a suppressions file.

## Not built

Compliance scoring or checklists; LLM-generated recommendation text; inferring user count; new detectors;
a profile stored in the database or edited in a UI. Evaluation of usefulness is **not done**
(plan in the spec, section 14).

## Alternatives rejected

- **LLM-generated advice:** non-deterministic, unverifiable references, and it would put unreviewed
  text next to findings. An optional rewording may come later under ADR-017/018.
- **Compliance scoring:** a percentage or "compliant" label would claim something static analysis
  cannot know, and invites misuse as an audit result.
