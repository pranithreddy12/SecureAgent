# ADR-041: A config-derived allow-list reset, and per-element tuple-return taint

- **Date:** 2026-10-14
- **Status:** Accepted (owner, re-scanning the same real report after ADR-040: "why am i still
  seeing false sql injection based threats")

## Context

ADR-040 fixed the reported project's `_cfg(name)` validator gap, but three of its eight false
positives (`app.py:505, 512, 543`) stayed flagged. Debugged against the owner's actual files
(`08-18-2026-Kevinbud-Project/Website/app.py`), not a guess:

1. `parse_sort(cfg)` allow-lists `sort` the standard way (`if sort not in sortable: sort =
   cfg["default_sort"][0]`), but resets to a value read from `cfg` (a validated config object),
   not a literal. `_resets_to_default` only recognised a literal constant or a parameter with a
   constant default, so `sort` stayed "tainted" even though every path through the function leaves
   it either already allow-listed or reset to one of config's own values.
2. `build_where(cfg, q)` returns `(where, params)`: `params` genuinely carries `q` (for bound `?`
   placeholders -- correct and safe), `where` (the actual SQL text) is built only from `cfg`. The
   engine marked a call's return tainted if *any* part of it was, so unpacking the tuple tainted
   `where` too, purely because its sibling `params` was.

## Decision

- `_resets_to_default`: also accept a reset value built only from constants, subscripts and
  attribute access rooted in one of the function's *other* parameters (`_param_lookup`) -- "the
  default from config," trusting that parameter the same way a one-hop allow-list guard already
  does. A reset to `request.*` or any other dynamic expression is unaffected (still flagged).
- `_function_tainted`'s fixpoint loop: for a multi-target assignment whose value is a call to a
  same-file function all of whose `return`s are literal tuples/lists of the same arity
  (`_tuple_return_mask`), taint each target by its *own* position in that tuple instead of the
  whole value. Falls back to the existing whole-value check for anything else (single return
  value, mismatched arity, a non-tuple return mixed in, chained assignment to the same call).

## Verification

Both reproduced and fixed against the owner's real file directly (not just a synthetic repro):
`app.py:505/512/543` dropped from "high/likely" taint findings to nothing; the file's one genuine
unguarded case from ADR-040's repro stayed flagged. Full project re-scan:
`08-18-2026-Kevinbud-Project` now reports 14 findings, zero "high" severity -- the remaining SQL
findings are the honestly-lower-confidence `static:sinks` structural flags (medium/suspicious) the
owner's own rebuttal already treated as acceptable defense-in-depth, not false positives.

4 new tests in `tests/test_realworld_fp.py` (the config-derived reset, the tuple-return mixed
safety case, and each one's "still a real finding" counterpart). Full backend suite: 577 passed, 2
skipped. Benchmark corpus unchanged 97%/97%. Full recall re-run across all eleven untouched sets:
identical per-app numbers to before both fixes (273/361 = 76% overall) -- zero regression.

## Not claimed

Same scope limits as ADR-040 (same-file, position-insensitive, best-effort). The tuple-return fix
only recognises a callee whose *every* return is a literal tuple of matching arity; a function that
sometimes returns a tuple and sometimes a bare value, or returns a tuple built via `*args`/a
variable, falls back to the coarser whole-value check. A chained assignment to a tuple-returning
call (`a = b = f()`, rather than `a, b = f()`) would be mis-attributed if it occurred -- not seen in
any real or test code, not specially handled.
