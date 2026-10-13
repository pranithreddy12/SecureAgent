# ADR-029: A sixth untouched set, measured without changing any detector

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with a sixth untouched set")

## Decision

Freeze planted-flaw lists for skf-labs (Python), DVGA and Damn-Vulnerable-RESTaurant (`9cb3618`), score the
scanner **unchanged**, record the result.

## Result

39/57 (68%). Pooled untouched recall over six sets 146/283 (52%); including tuned-on fixes 220/283 (78%).

## Not claimed

The set is easier than earlier ones (tiny single-file labs, 10 literal-secret hits); excluding secrets it is
63%. The only real application in it (DVGA) scored 1/7. "About half, up to two thirds on simple code" is
the honest expectation for unseen vulnerable apps. Truth lists were written by a model, not an independent
human.
