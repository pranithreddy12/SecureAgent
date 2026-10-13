# ADR-035: A tenth untouched set, measured without changing any detector

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "proceed with a tenth untouched set")

## Decision

Freeze planted-flaw lists for two further applications, built as minimal, deliberate reproductions of the
ADR-031 (cross-file sink) and ADR-034 (if/else-branch-assignment) hypotheses rather than a random sample
(`897d424`), score the scanner **unchanged**, record the result.

## Result

6/12 (50%). Pooled untouched recall over ten sets 183/344 (53%).

## Consequence

- ADR-034's hypothesis holds: a value assigned in one branch of a plain `if`/`else` and used *after* the
  statement does not carry taint; the same value consumed *inside* the branch that assigns it does.
- ADR-025's structural SQL rule is taint-source-agnostic (it matches the f-string-into-`execute`/`text`
  shape regardless of provenance), which is why a same-file, parameter-fed SQL injection was found while
  the identically-shaped command injection was not -- there is no equivalent structural rule for
  `command_injection`. Some of ADR-026/031's "cross-file"/"parameter-fed" framing is really "which classes
  have a structural rule", not one taint-engine limitation across all classes.
- Two new, narrow gaps: the IDOR check does not recognise `flask_login.current_user` as an ownership
  identity (only `request.user`); the mass-assignment check does not recognise `obj.__dict__.update(d)`.
- Recorded, not treated as a near-term fix: a stored value mutated in one handler and rendered unescaped in
  another requires modelling state across handlers, not a taint-tracking fix.

None fixed here.
