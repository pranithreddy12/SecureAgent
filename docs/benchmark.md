# Detector accuracy benchmark

`secureagent benchmark <corpus-dir>` measures precision and recall against a labelled corpus.
Every line that should produce a finding carries a `VULN:<finding_type>` comment; the scanner runs
over the directory and each finding is matched to a marker by (file, line, type).

| Outcome | Meaning |
|---|---|
| true positive | marker and a finding of that type on that line |
| false negative | marker with no matching finding (a miss) |
| false positive | finding with no marker (everything unmarked is, by definition, safe) |

```bash
cd backend
secureagent benchmark benchmark/corpus                              # report
secureagent benchmark benchmark/corpus --min-precision 0.9 --min-recall 0.9   # gate (exit 1)
```

## What the numbers mean (and don't)

The bundled corpus (`backend/benchmark/corpus/`, 4 files, ~36 labelled cases plus safe
counterparts) was **written by the project**, using patterns the detectors were built for.
It therefore measures *regressions and known weaknesses*, **not** the detection rate on real
applications. It is deliberately seeded with:

- **known misses** (second-order SQL injection, a business-rule IDOR through a plain dict), and
- **known false positives** (an allow-listed host that is still reported as SSRF; a catalogue
  lookup by id reported as IDOR),

so the numbers are not a flattering 100%. The corpus check in `tests/test_benchmark.py` fails if
precision or recall drops below 90% or if the corpus shrinks.

For a real-world figure, point the command at a larger labelled corpus (for example an OWASP
benchmark checkout annotated with `VULN:` markers); no changes to the harness are needed.

## Latest result (2026-10-10, bundled corpus)

| | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| overall | 32 | 2 | 2 | 94% | 94% |

Known misses: `py_injection.py` second-order SQL injection; `py_access_logic.py` plain-dict IDOR.
Known false positives: allow-listed SSRF host; catalogue lookup flagged as IDOR.

## What the first run found

Running the benchmark for the first time exposed two real detector gaps that unit tests had not:

| Finding | Fix |
|---|---|
| Python `redirect(request.args["next"])` was not reported (open redirect only existed for JS) | Open-redirect sinks added to Python taint (`redirect`, `RedirectResponse`, `HttpResponseRedirect`); `url_for(...)` targets excluded |
| `eval("1 + 1")` (a constant) was reported as code injection | `eval`/`exec` of a literal string is no longer flagged |

It also exposed labelling mistakes in the first draft of the corpus (unauthenticated POST routes that
*were* real findings but were not labelled) -- corrected by guarding those routes, not by loosening
the matcher.
