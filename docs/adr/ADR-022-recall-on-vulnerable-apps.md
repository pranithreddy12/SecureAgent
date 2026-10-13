# ADR-022: Recall against planted vulnerabilities

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with the known-vulnerable set"; downloading approved)
- **Relates to:** ADR-021 (real-project evaluation), `docs/evaluation.md`

## Context

ADR-021 measured precision but could not measure recall: real projects have no list of what is wrong.
Intentionally vulnerable applications do.

## Decision

1. Record planted flaws for five public applications (file, line, class, note) in
   `backend/benchmark/known_vulnerable.json`, pinned to commit hashes, with `in_taxonomy: false` for
   classes with no detector so they are visible but not counted.
2. `python -m app.evaluation recall --apps DIR` scores findings against it (same file, matching type
   family, within 3 lines) and lists findings inside patched twin directories as false-positive
   candidates.
3. Fix each miss as a general rule, with a regression test (`tests/test_known_vulnerable.py`); the
   applications themselves are downloaded on demand and never vendored or executed.

## Result

22 of 34 (65%) before, 33 of 34 (97%) after fixes made on the same applications.

## Not claimed

- The 97% is tuned-on and not independent; 65% is the pre-fix figure.
- Taxonomy gaps are real gaps: 8 planted flaws have no detector.
- Policy change disclosed: a placeholder-looking value under a secret-named key (`cookieSecret:
  "session_cookie_secret_key_here"`) is now reported as a low "placeholder-style credential" instead of
  being ignored; the benchmark corpus line that expected silence now expects that low finding, and the
  demo test was rewritten accordingly. The benchmark moved 35/36 -> 36/37 TP.

## Consequences

- New behaviours: `do_GET` handlers' `self.path/headers/rfile` are request input; `send_header("Location",
  <input>)` is an open redirect; XML parsing a module-level literal is not reported; `env/` directories
  that are not virtualenvs are scanned; JS taint covers earlier-line queries, `req.files`, `needle`/`got`/
  `axios.get`; `unserialize()` and libxmljs `noent: true` are reported; in-handler session gates
  (`'x' not in g.session` + redirect) and `authenticate()` calls count as guards.
