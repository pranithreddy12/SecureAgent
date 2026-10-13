# ADR-025: Third held-out set and structural rules

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with the third held-out app set")
- **Relates to:** ADR-022, ADR-024, `docs/evaluation.md`

## Decision

1. Freeze planted-flaw lists for five further applications before scoring (`150fec2`); add `clean_files`
   negatives and class families (`mass_assignment`, `sensitive_data_in_log`, `template_autoescape_off`,
   `missing_authorization`) to the evaluator.
2. Score as-is, then fix generically with tests (`tests/test_third_set_fixes.py`).

## Result

Untouched 26/64 (41%); after fixes 52/64 (81%, tuned-on). Benchmark 97% / 97%. Backend 562 passed.

## Detector changes

- OpenAPI/connexion `operationId` handlers and routes (`app/analysis/openapi_spec.py`), with security
  taken from the operation or the document.
- Structural SQL: Python strings built by f-string / `%` / `+` / `.format` passed to `execute`/`text`
  (numeric casts exempt); JS `query/execute` with concatenation or interpolation, including a variable
  built just above.
- JS: NoSQL filter variables built from request values, `.find(body)`; `new X(req.body)` mass assignment;
  secrets in `console.log`; `extractAllTo`; `res.location` / `res.download`; reflected XSS in `res.send`
  unless escaped; redirects validated by `startsWith`/allow-list are not reported; `new Function` with a
  dynamic body is not a "constant call".
- Python: `debug=True` / `autoescape=False` keywords on any application/template call; secrets in
  `config['KEY'] = '...'`; express-session `secret: '<phrase>'`.

## Not claimed

- 81% is tuned-on; 41% is the honest number. Structural rules trade precision for recall and fire without
  a request source. Spec parsing is a small YAML-subset reader, not a YAML parser.
