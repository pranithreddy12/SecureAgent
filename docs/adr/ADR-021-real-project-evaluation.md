# ADR-021: Evaluate on real projects, and fix what it finds

- **Date:** 2026-10-13
- **Status:** Accepted (owner: "proceed with phase 4")
- **Relates to:** ADR-020 (MCP trust layer), `docs/paper/PAPER_PLAN.md` (RQ1)

## Context

Every accuracy figure so far came from a corpus the author wrote while tuning the detectors (97% / 95%).
An earlier real-project scan had already shown much lower precision, and an assistant comparison showed
more gaps. Phase 4 of the MCP plan asked for a measurement on code the scanner was not written against.

## Decision

1. Add `app/evaluation.py` (`prepare` / `score`): a stratified, redacted labelling sheet and an honest
   scorer (unsure and unlabelled are reported, recall comes only from supplied `extras`).
2. Run it on eight of the owner's own projects (development set, 111 findings) and fourteen others
   (holdout, 34 findings). A model produced a first-pass label for every sampled finding.
3. Fix each systematic cause as a general rule, never as a path or project exception, with a regression
   test pairing the false positive with its nearest real variant.
4. Downgrade `swallowed_exception` to informational unless the `try` body is a security-relevant
   operation: it was 0 of 9 on the holdout.

## Result

Precision on the same sampled items: 28% -> 82% (development), 59% -> 83% (holdout); 23 of 30 and 19 of 19
real findings kept. The benchmark is unchanged (97% / 95%). Detail and limits: `docs/evaluation.md`.

## Not claimed

- **Not independent.** The labeller is a model, not the code's author, and the samples guided the fixes
  (the holdout was also seen before the swallowed-exception rule), so the "after" numbers are optimistic.
- **Not a population rate.** Stratified small samples.
- **No recall.** There is no independent ground truth of real issues; the with/without-MCP model
  comparison needs runs that cannot be made from this environment.
- Seven development-set real findings were lost to the new rules (six swallowed exceptions that are now
  informational, one inconsistent-authorization outlier whose siblings use optional authentication).

## Consequences

- New detector behaviour: `get_current_*_optional` is not a guard; `Depends(current_*)` is; public-by-design
  paths are not reported as unguarded; JS `api.*` client calls are not routes outside server files;
  `os.environ.get("X_SECRET", "...")` is reported but descriptive keys and identifier values are not.
- A third, untouched set labelled by a human is the next step and the basis for any claim in the paper.
