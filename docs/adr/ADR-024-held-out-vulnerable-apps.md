# ADR-024: Held-out vulnerable applications (pygoat, Juice Shop)

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with pygoat and juice shop"; downloading approved)
- **Relates to:** ADR-022, ADR-023, `docs/evaluation.md`

## Context

Recall had been scored only on applications the detectors were then tuned against, so every "after"
figure was optimistic. Two further applications were available that no rule had been designed on.

## Decision

1. Clone pygoat and Juice Shop at pinned commits; write each planted-flaw list **before** scanning and
   commit it (`95d4163`) so the order is auditable; mark them `held_out` in
   `backend/benchmark/known_vulnerable.json`.
2. Score the scanner **as it was**, record that number, and only then fix the misses generically, adding
   regression tests (`tests/test_heldout_fixes.py`).
3. Label a stratified sample of the findings on these applications to see what the fixes cost in
   precision.

## Result

- Untouched held-out recall: **23/47 (49%)**; pygoat 73%, Juice Shop 28%.
- Seven applications, 89 planted flaws: **51% untouched (45/89)**, 94% after fixes (tuned-on).
- Precision on the labelled sample: 73% -> 77% after the precision round; 53/53 real findings kept.

## Not claimed

- 94% is not independent; 49% is the honest number for code the scanner has not been tuned on.
- Teaching-snippet directories and vendored libraries inflate Juice Shop's finding count; no vendor
  detection was added.
- Template-level flaws (Django `|safe`, Angular templates) remain invisible to a scanner that reads
  views and TypeScript only.

## Consequences

- JavaScript taint: TypeScript annotations, `req.*` aliases, derived variables (3 passes), handler
  destructuring, `vm.run*`, constant-literal arguments are ignored; `yaml.load` is low severity.
- New sink rules: `createHash('md5'|'sha1')`, libxml2 `XML_PARSE_NOENT`, `bypassSecurityTrust*`, hardcoded
  key literal in `createHmac` / `jwt.sign` / `jwt.verify`; Python `X.eval(input)` and
  `setFeature(external_ges, True)`.
- Guards: `request.user.is_authenticated` (functions and class-based views) counts as authentication.
