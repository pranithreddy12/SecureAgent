# ADR-030: A seventh untouched set, measured without changing any detector

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "proceed with a seventh untouched set")

## Decision

Freeze planted-flaw lists for three further applications (`3cd70d2`), score the scanner **unchanged**,
record the result.

## Result

12/16 (75%). Pooled untouched recall over seven sets 158/299 (53%).

## Consequence

Two narrow JS taint gaps recorded, not fixed here: a URL read via `url.parse(req.url, true).query` rather
than `req.query`, and a sink expression returned directly inside a template literal (`` res.send(`...${x}`) ``,
`` client.query(`...${x}`) ``) without an intermediate assignment.
