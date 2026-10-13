# ADR-031: An eighth untouched set, measured without changing any detector

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "proceed with an eighth untouched set")

## Decision

Freeze planted-flaw lists for two further applications chosen to stress cross-file request flow
(`f48f10b`), score the scanner **unchanged**, record the result.

## Result

8/19 (42%). Pooled untouched recall over eight sets 166/318 (52%).

**Correction (2026-10-14, ADR-036):** two of these counted misses (`vuln-nodejs-app:79`,
`VulnNodeApp:127`) were my own truth-list line-pointing errors, not scanner gaps; both are genuinely
`found`, a few lines from where I pointed. Corrected: 10/19 (53%). See ADR-036.

## Consequence

Confirms, with a deliberately adversarial pick, that taint tracking does not follow a request value across
a function call into another file: VulnNodeApp (route -> controller -> model, every sink in a different
file from the request read) scored 2/8; vuln-nodejs-app (route calls the sink directly, same file) scored
6/11, in line with other sets. This is a bigger version of the parameter-fed-sink gap recorded in ADR-026,
not a new class of gap. Not fixed here -- cross-file call-graph tracing is a larger change than a
single-pass fix and needs its own design, not a quick patch validated by reusing this same set.
