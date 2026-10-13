# ADR-028: Fifth untouched set (Pixi, DVSA, crAPI)

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with a fifth untouched set")

## Decision

Freeze 19 planted flaws for three applications before scoring (`784f091`) and score the scanner
unchanged (post ADR-027).

## Result

11/19 (58%). Five untouched sets: 52 / 49 / 41 / 46 / 58%, pooled 107/226 (47%).

## Notes

- Small set (19 flaws); one reader; the applications span Express/Mongo, serverless and DRF.
- Large finding counts (Pixi 108, crAPI 132) come from per-route "unguarded" reports, structural NoSQL
  findings and logging rules, not from additional real flaws.
- No detector was changed. Remaining gaps recorded: Mongo operator injection in `findOne({..: user})`
  through helper parameters, `is_admin` mass assignment from `req.body` conditionals, `eval` of a
  string built from event fields (Python), DRF class-based-view BOLA.
