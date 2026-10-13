# ADR-036: Retracting the "if/else taint gap" (ADR-034, ADR-035); five truth-list errors fixed

- **Date:** 2026-10-14
- **Status:** Accepted (owner: "fix the if/else taint gap")

## Decision

Before touching `app/analysis/taint.py`, reproduce the claimed gap in isolation. It did not reproduce.

```python
# minimal repro: a value assigned in one branch of if/else, used after the statement
if request.method == "POST":
    user_in = request.form["in"]
else:
    user_in = "default"
return "<h1>Hello " + user_in   # flagged reflected_xss immediately
```

`_function_tainted`'s fixpoint loop (`app/analysis/taint.py`) collects every assignment in the function
with `ast.walk(func)` (via `_collect_assignments_lined`), which visits `If.body` and `If.orelse` exactly
the same way it visits everything else -- it has no concept of "branch" at all. It was never
control-flow-sensitive in the way ADR-034 and ADR-035 described, so there was nothing to fix there.

## What was actually happening

Re-running the scanner directly (not through the eval harness) against the real files named in the
ninth and tenth sets' truth list found every one of the four supposedly if/else-caused misses as a
genuine, correctly-placed finding a few lines away from where I had pointed the truth entry:

| Truth entry (mine) | Real finding | Gap |
|---|---|---|
| `vuln-nodejs-app/controllers/vuln_controller.js:79` | `sql_injection` at `:83` | 4 |
| `VulnNodeApp/utils/utility.js:127` | `xxe` at `:122` (the `noent: true` key, not the call) | 5 |
| `VAPI-folmer/vAPI.py:73` | `sql_injection` at `:77` | 4 |
| `VAPI-folmer/vAPI.py:305` | `command_injection` at `:316` | 11 |
| `testing-sites/level4/app.py:29` | `command_injection` at `:19` (inside the callee) | 10 |

`LINE_TOLERANCE` (`app/evaluation.py`) is 3 lines. In every case I had pointed the truth entry at the
*source* line (the assignment, or the call site in the caller) rather than the actual sink line the
scanner reports (the `execute`/`popen`/`subprocess.run` call, which can sit several statements, or an
entire function, below). These are authoring mistakes in `benchmark/known_vulnerable.json`, not scanner
behaviour, and are now fixed by moving the line number to the real sink line -- no class, file, or pass/
fail verdict was changed, and no detector code was touched.

One claimed miss turned out to be real, for a different reason than claimed:

- **`testing-sites/level1/app.py:15`**: `return_xss`/`_html_with_input`
  (`app/analysis/extra_detectors.py`) requires an HTML tag string **literal** in the same return
  expression before it looks at taint at all. `level1` builds its response from
  `open("./templates/index.html").read() % user_in` -- the markup lives in a file, not a literal in
  `app.py`, so the literal-tag check fails before taint is even consulted. Confirmed by reproducing the
  identical if/else-assigned value with the HTML inlined as a literal: it was flagged immediately. This
  is a real, narrow gap (a file-sourced template is invisible to this one check) -- but it is a sink-
  detection gap, not a control-flow one, and it is not what ADR-034 or ADR-035 claimed.

## Result

Five lines corrected in `benchmark/known_vulnerable.json` (no detector change). Corrected recall:

| Set | Before | After |
|---|---|---|
| Eighth (ADR-031) | 8/19 (42%) | 10/19 (53%) |
| Ninth (ADR-034) | 11/14 (79%) | 13/14 (93%) |
| Tenth (ADR-035) | 6/12 (50%) | 7/12 (58%) |
| **Pooled untouched, ten sets** | 183/344 (53%) | **188/344 (55%)** |

## Consequence

- The if/else claim in ADR-034 and ADR-035 is retracted; both files are annotated pointing here rather
  than rewritten, so the record shows what I believed at the time and why it was wrong.
- ADR-031's cross-file-taint conclusion stands, corrected to 3/8 (38%) for VulnNodeApp vs 7/11 (64%) for
  vuln-nodejs-app -- still a real, confirmed gap, just smaller than first measured.
- The one narrow gap this correction surfaced honestly -- a reflected-XSS sink built from file content
  rather than a literal -- is recorded in `docs/evaluation.md`'s tenth-set section, not fixed here.
- Lesson for future truth-list entries: point at the line the scanner would actually report (the call
  inside the sink, including inside a callee), not the line where the tainted value is first built or
  called from -- and verify with a direct `scan_repo` run before freezing, not only the eval harness's
  pass/fail summary.
