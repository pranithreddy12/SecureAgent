# ADR-040: Allow-list validation through a helper function, not just inline

- **Date:** 2026-10-14
- **Status:** Accepted (owner reported a real audit's SQL-injection findings as false positives,
  pasted a correctness review of the report against the actual code: "i need the agent to be
  accurate please fix this")

## Context

The reported project validates a request-derived dataset name through a small helper before using
it directly as a SQL table name:

```python
def _cfg(name):
    cfg = DATASETS.get(name)
    if not cfg:
        abort(404)
    return cfg

@app.route("/<name>/")
def listing(name):
    cfg = _cfg(name)
    ...
    db().execute(f"SELECT * FROM {name} ...")   # `name` itself, not `cfg`
```

The taint engine already modelled an inline allow-list guard (`if host not in ALLOWED: return` ->
`_allowlist_guarded`), but only within the *same* function, and only for a direct membership test.
It did not recognise:

1. the `X = D.get(key); if not X: abort()` shape (an allow-list check spelled as a dict lookup,
   not a membership test), or
2. a guard performed *inside a helper function* the caller invokes before using the value.

8 of the report's 18 findings (all SQL injection, "likely", "high") were false positives as a
result: `name` can only ever be one of `DATASETS`'s own keys by the time it reaches any sink,
in every route, because every route calls `_cfg(name)` first.

## Decision

`app/analysis/taint.py`:

- `_dict_lookup_guard_name`: recognises `cfg = D.get(name)` / `if not cfg` (or `is None`) as
  equivalent to a direct membership guard on `name` -- but only when the `.get()` call is already
  `_sa_const` (`_mark_constant_lookups`: `D` is a module-level dict literal assigned exactly once,
  never mutated). If `D` is written to elsewhere with request data, this guard does not fire
  either -- a key being "allowed" says nothing about whether the table's own *values* are safe,
  and an existing regression test already covered exactly that case.
- `_validator_guarded_param`: a function is a "validator" for one of its own parameters if its
  body guards that parameter (by the above, or the pre-existing direct-membership check) and exits
  otherwise.
- `_cross_function_guarded`: in the *caller*, a simple-name argument passed to a known same-file
  validator at its guarded parameter's position is guarded too -- the call could not have returned
  normally with a disallowed value. One hop only, same-file only, position-insensitive (consistent
  with the existing inline guard's stated limits).
- `_allowlist_guarded(func, ctx)` now combines both; `_function_tainted` passes `ctx` through.

## Verification

Reproduced the exact shape in a scratch file and confirmed 3 of 4 planted sinks (same-handler
direct use, same-handler via a further helper call, a second handler) dropped from "high/likely" to
nothing, while an unguarded fifth sink in the same file stayed "high/likely" -- compared against
the unpatched engine on the same file via `git stash` to confirm the before/after delta precisely.
Full backend suite: 573 passed, 2 skipped (3 new tests in `tests/test_realworld_fp.py`, including
one that reproduces the owner's exact report pattern and one confirming the "no abort" / "no call"
variants are still caught). Benchmark corpus unchanged at 97%/97%.

A first pass of this fix (without the `_sa_const` requirement) broke an existing regression test
(`test_the_nearest_real_variants_are_still_reported`'s "mutated table" case) by coincidentally also
suppressing an unrelated, already-correct detection of a dict mutated with request data. Tying the
new guard to `_sa_const` fixed it without weakening either protection -- documented here so the
interaction isn't lost again.

## Not claimed

Same-file only (a validator imported from another module is not recognised); one hop only (a
validator that itself delegates to a second validator is not chased); still vulnerable to a
validator whose guard body itself contains a bug the scanner doesn't model. The report's other
findings (the two `static:sinks` "suspicious" SQL findings, "missing authorization", "container
runs as root", "XML entity expansion") were reviewed against the owner's rebuttal and were already
correctly labelled lower-confidence/contextual -- nothing else was changed.
