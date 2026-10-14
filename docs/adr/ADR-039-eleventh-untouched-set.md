# ADR-039: An eleventh untouched set, measured without changing any detector

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "proceed with an eleventh untouched set")

## Decision

Freeze planted-flaw lists for three further applications (`d92dc17`), score the scanner **unchanged**,
record the result. Following ADR-036, every truth-list line was checked against a direct `scan_repo` run
before freezing, not inferred from reading the source.

## Result

11/17 (65%). Pooled untouched recall over eleven sets 199/361 (55%).

## Consequence

Two new, narrow, vocabulary-only gaps (not taint-engine limitations): the secrets fallback rule doesn't
recognise the `os.getenv(x) or "literal"` form (only `os.getenv(x, "literal")`); the JS structural SQL
rule's sink-call list doesn't include pg-promise's `db.one`/`db.many`/`db.any`. Also confirmed, by direct
verification before freezing rather than after scoring, that the structural `command_injection` and
`sql_injection` rules fire regardless of whether the tainted value is provably `request`-sourced -- a CLI
script's `input()` triggered both. Not fixed here.
