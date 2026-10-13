# Real-project evaluation (MCP plan phase 4, paper RQ1)

The author-written benchmark (`secureagent benchmark`, 97% / 95%) is a regression guard: the detectors
were tuned against it. This page records what happened when the scanner was run on projects it had not
been written against, how the numbers were produced, and what they do **not** show.

## Method

`python -m app.evaluation prepare REPO... --out DIR` scans each repository and writes `labels.json`: a
sample of findings **stratified by finding type** (default 6 per type, most severe first), each with a
redacted code excerpt and an empty `label`. A reader fills in `true` / `false` / `unsure` (and may add
`extras`: real issues found another way, with `found_by_tool`). `python -m app.evaluation score` prints
per-type precision, the unlabelled and unsure counts, and a recall estimate from the extras.

Rules: only labelled items count; `unsure` is reported, not hidden; informational and
suppressed findings are not sampled; the overall figure of a stratified sample is **not** a population
rate.

## What was run (2026-10-13)

| Set | Projects | Findings sampled | Role |
|---|---|---|---|
| Development | 8 of the owner's own projects (Python/FastAPI, NestJS, Next.js, Flask, scripts) | 111 | used to find and fix systematic false positives |
| Holdout | 14 other small projects (Flask, Express, React, scripts) | 34 | measured after the first round of fixes |
| Third | 23 remaining local projects, mostly tiny scripts and static sites (one is a near-duplicate of a development project) | 42 | scanned **before** its failures were fixed: the only set that tests the code as it was |

**Labelled by Claude (a model), from reading the excerpts and, where needed, the surrounding code.
Not independently verified by a human.** That is a real limitation: the labeller can be wrong, and is
not the code's author.

## Results

| | Precision before fixes | After fixes (same items) | Real findings kept |
|---|---|---|---|
| Development sample | 28% (30 / 106) | 82% (23 / 28) | 23 / 30 |
| Holdout sample | 59% (19 / 32) | 83% (19 / 23) | 19 / 19 |
| Third set | **48% (20 / 42)** -- measured on the code as it stood | 56% (20 / 36) | 20 / 20 |

**The third set is the honest generalisation figure: 48%.** It was labelled before any fix was made for
it. All 22 of its false positives were `xss_sink` (`innerHTML` assignments of escaped or constant data in
static sites and small UIs); the other three types were 100% (20 / 20). Fixing that class (escaped,
numeric, literal-choice and constant-table interpolations; files that read no input or network report
only as low) moves the same items to 56%. Those 16 remaining items are still reported, as low
severity, because an `innerHTML` assignment whose data arrives from another file cannot be judged by a
per-file scan.

- Per type, before fixes: `missing_function_level_authorization` 9%, `idor` 17%, `sql_injection` 0%,
  `hardcoded_secret` 41%, `swallowed_exception` 29%; `container_runs_as_root` and `unbounded_query`
  100%.
- The seven "lost" real findings in the development set are one inconsistent-authorization item (its
  siblings used *optional* authentication, so it stopped being an outlier) and six swallowed-exception
  items that are now informational because the `try` body is not a security operation.

## What the failures were (all fixed, with regression tests in `tests/test_eval_regressions.py`)

| Class | Cause |
|---|---|
| Missing authorization (9% -> ) | `Depends(current_org)` / `get_current_active_user` not recognised as guards; NestJS `@UseGuards` above `@Controller`; JS *client* calls (`api.put("/x")`) parsed as routes; public-by-design paths (token URLs, login, register, webhooks) |
| IDOR (17% -> ) | ownership check on `organization_id` not recognised; repositories scoped at construction (`Repo(db, user.tenant_id)`); in-memory `*_store.get(code)` treated as a database |
| SQL injection (0% -> ) | SQLAlchemy statement variables (`stmt = select(...).where(...)`) executed later; a same-file helper judged by its arguments instead of its return value |
| Hard-coded secrets (41% -> ) | enum members, storage-key names, type aliases, `tokenUrl`, `MAX_TOKENS`, blockchain addresses, README prose, placeholder fallbacks |
| Misc | `Path(x).name` and character-filter joins as path sanitizers; constant `innerHTML` markup; `int(md5(...).hexdigest(), 16)` bucketing; narrow or commented `except ... : pass` |

## What this does and does not show

- **Shows:** the first real-project precision (28% on the development sample) was far below the
  benchmark's 97%, the causes were systematic, and they are fixed.
- **Shows:** each evaluation round found a new class of noise the previous ones had not (guards and ORM
  statements, then `swallowed_exception`, then `innerHTML`); the fixes generalise only partly. Expect
  precision on unseen code to be well below the development-set figure until more rounds are done.
- **Does not show:** a population precision. The samples are stratified and small; the same samples
  guided the fixes, so the "after" figures are optimistic (the holdout was also seen before the final
  swallowed-exception rule). A clean estimate needs a **third, untouched set** labelled by someone who
  knows the code.
- **Recall is unmeasured.** No independent list of real issues was available; the recall estimate in the
  harness is only as good as the `extras` supplied. The with/without-MCP comparison (phase 4 proper)
  needs model runs that could not be made from this environment.
- The benchmark is unchanged at 97% / 95%; the fixes did not regress it.

## Reproduce

```bash
python -m app.evaluation prepare path/to/repo1 path/to/repo2 --out eval_run
# edit eval_run/labels.json: set "label" on every item, add "extras", set "labelled_by"
python -m app.evaluation score eval_run/labels.json
```

Keep `labels.json` out of version control: it contains code excerpts.

## Recall on intentionally vulnerable applications (2026-10-13)

Precision needs a reader; recall needs a list of what is really there. Five public applications that
*plant* their flaws were cloned at pinned commits, read by hand, and every planted flaw was recorded
(`backend/benchmark/known_vulnerable.json`). `python -m app.evaluation recall --apps DIR` scores the scanner
against that list: a flaw counts as found when a finding of a matching type sits in the same file within 3
lines. Flaws in classes the scanner has no detector for (template injection, NoSQL injection, XPath
injection, insecure session design, plaintext passwords) are listed as *outside the taxonomy* and are not
counted -- they are reported so the figure is not flattered by omission.

| Application | Language | Planted (in taxonomy) | Found before | Found after |
|---|---|---|---|---|
| DSVW | Python | 9 | 4 | 9 |
| Vulnerable-Flask-App | Python | 7 | 7 | 7 |
| vulpy (`bad/`) | Python | 4 | 4 | 4 |
| dvna | JavaScript | 7 | 3 | 6 |
| NodeGoat | JavaScript | 7 | 4 | 7 |
| **Total** | | **34** | **22 (65%)** | **33 (97%)** |

- **65% is the honest number.** It was measured before any change was made for these applications.
- **97% is not independent.** The misses were fixed *using these same applications*, so it shows the
  fixes work, not that the scanner finds 97% of planted flaws in code it has not seen.
- What the misses were: `BaseHTTPRequestHandler` requests (`self.path`) not seen as input; a `Location`
  header from a parameter; JS SQL queries built on an earlier line; `needle` / `axios.get` as SSRF
  clients; `node-serialize` `unserialize()`; libxmljs `noent: true`; configuration directories named
  `env/` skipped as virtualenvs; placeholder-style secrets under `cookieSecret`-type keys.
- Still missed: dvna's Sequelize `User.find({where: {id: req.body.id}})` (IDOR in JavaScript).
- Eight planted flaws are outside the taxonomy: SSTI x3, XPath injection, reflected XSS in string
  formatting, NoSQL injection, insecure session cookie, plaintext password storage.

### False positives on the patched twin

vulpy ships a vulnerable `bad/` and a patched `good/` of the same code. The SQL injections correctly
disappear in `good/`. The scanner still reports 10 findings there: 4 are real (a hardcoded JWT secret, two
`debug=True`, a swallowed exception around session loading), 2 are in attack-tooling scripts, and 4 are
"no visible authorization" on endpoints that are public by design (sign-up, key creation by credentials,
public reads).

### Limits

- Five applications, 34 planted flaws, one reader (a model). Small and tuned-on.
- "Planted" lists are what I found by reading, not an official register; a flaw I overlooked is not
  counted either way.
- Intentionally vulnerable applications are denser in flaws and simpler in structure than production
  code. Do not read 97% as a real-world recall.
