# ADR-034: A ninth untouched set, measured without changing any detector

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "proceed with a ninth untouched set")

## Decision

Freeze planted-flaw lists for three further applications, one chosen to mix a connexion handler-argument
source (already supported) with a `connexion.request.get_json()`/`.headers` source in the same file
(`bd84e4b`), score the scanner **unchanged**, record the result.

## Result

11/14 (79%). Pooled untouched recall over nine sets 177/332 (53%).

**Correction (2026-10-14, ADR-036):** the "if/else" diagnosis below is retracted. `vAPI.py:73` and
`vAPI.py:305` were my own truth-list line-pointing errors, not scanner gaps; both are genuinely `found`.
Corrected: 13/14 (93%). See ADR-036 for the reproduction that disproved the if/else claim.

## Consequence (superseded by ADR-036 -- kept for the record)

`connexion.request.*` is not uniformly a blind spot -- two of three call sites using it were found. The
real pattern in the two misses: a variable assigned inside one branch of a plain `if`/`else` (not a
ternary) is not reliably carrying taint afterwards, in this file at least. A third miss is a detector
vocabulary gap in the `redos` rule's regex shapes, unrelated to taint. None fixed here; a tenth untouched
set would be the way to confirm the `if`/`else` characterisation before spending a fix on it.
