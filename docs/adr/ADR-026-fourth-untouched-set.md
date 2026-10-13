# ADR-026: A fourth untouched set, measured without changing any detector

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with a fourth untouched set")

## Decision

Freeze planted-flaw lists for four unseen applications (`48db15c`), score the scanner **unchanged**, and
record the result. No fixes in this step, so the number is clean.

## Result

25/54 (46%). With the earlier untouched measurements (52%, 49%, 41%) the pooled untouched recall is
96/207 (46%). After the earlier tuned-on fixes the scanner reaches 160/207 (77%) over everything.

## Consequence

The largest remaining systematic gap is Django function views wired only through `urls.py` (0 of 11
annotated IDORs in django.nV); the second is parameter-fed sinks in helper functions. Both are recorded as
next work, not fixed here.
