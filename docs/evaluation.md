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

### After adding the missing detector classes (ADR-023)

Eight planted flaws had no detector. Seven new detector classes were added -- template injection, XPath
injection, NoSQL injection, reflected XSS in a returned HTML string, an unsigned session cookie, a
plaintext password, and JavaScript IDOR -- and all eight flaws were moved into the taxonomy and scored.

| Counting | Found | Of | Recall |
|---|---|---|---|
| In-taxonomy planted flaws before the new detectors | 33 | 34 | 97% (tuned-on) |
| **All** planted flaws, before the new detectors (outside-taxonomy ones count as misses) | 33 | 42 | **79%** |
| All planted flaws, after the new detectors | 40 | 42 | 95% (tuned-on) |
| All planted flaws, before *any* change for these apps | 22 | 42 | **52%** |

- **52% is the only untouched figure** (all planted flaws, scanner as it was before this evaluation).
  Everything later was fixed against these same five applications.
- Still missed: DSVW's reflected XSS built by a regex substitution into a buffer (not a `return`), and
  Vulnerable-Flask-App's template injection through an exception message (no request input is visible).
- **Cost on real code:** the new detectors report **nothing** on the 22 real projects used in the
  precision samples (0 new findings), so they did not add false positives there -- and, equally, there is
  no evidence yet that they find anything in real code.

## Held-out vulnerable applications: pygoat and juice-shop (2026-10-13)

No detector had been designed against these two. Their planted-flaw lists (47 flaws: 22 in pygoat, 25
in Juice Shop, the latter largely from the project's own `vuln-code-snippet vuln-line` annotations) were
written **and committed before the scanner was run on them** (git history shows the order).

| | Planted | Found, scanner as it was | Recall |
|---|---|---|---|
| pygoat (Django) | 22 | 16 | 73% |
| juice-shop (TypeScript / Express / Angular) | 25 | 7 | **28%** |
| **Held-out total** | **47** | **23** | **49%** |

**49% is the untouched held-out recall.** It matches the 52% measured on the first five applications
before anything was tuned (22/42), so the two untouched figures agree: *roughly half of planted flaws were
found by a scanner nobody had tuned on that application.*

What Juice Shop exposed: TypeScript type annotations (`let criteria: any = req.query.q`) broke the
JavaScript taint seed; `const query = req.query` aliases and `({ params, query }: Request)` handler
destructuring were not input; `vm.runInContext`, `createHash('md5')`, `createHmac('sha256', 'literal')`,
`jwt.sign(x, 'literal')`, `bypassSecurityTrustHtml`, libxml2 `XML_PARSE_NOENT` and multi-line Mongo
updates were not recognised. What pygoat exposed: `ImageMath.eval`, `xml.sax` external entities, a
session cookie named just `cookie` holding `user|expiry`.

After fixing those generically: **44/47 (94%)** -- tuned-on, so not independent. Overall across all seven
applications and 89 planted flaws: **51% untouched (45/89), 94% after (84/89).**

### Precision on the same applications

103 findings (5 per type per app) were labelled: 53 real, 20 false, 30 unsure (mostly Juice Shop's
`data/static/codefixes` teaching snippets and `csrf_exempt` API endpoints). Precision over labelled
items was 73%, and 77% after a second round of fixes (Django `is_authenticated` as a guard, `create_user`
hashes, `innerHTML ===` is not an assignment, constant arguments to `execSync` / `new Function`, js-yaml
`load` reported only as low). The same 53 real findings were kept.

### Still missed
- pygoat: a user blog written into a template file; two reflected-XSS labs whose flaw lives in the HTML
  template, not the view.
- DSVW: reflected XSS written into a buffer. Vulnerable-Flask-App: SSTI through an exception message.

### Limits
- Labels again by one model; the planted lists for pygoat/juice-shop are partly the projects' own markers
  and partly my reading.
- 30 of 103 sampled findings were "unsure" and are excluded from precision.
- Juice Shop produces 337 findings; most are third-party or teaching code. A real triage would suppress
  `data/static/codefixes` and vendored assets.

## Third held-out set: VAmPI, dvpwa, nodejs-goof, vulnerable-node, dvws-node (2026-10-13)

Truth lists (64 in-taxonomy planted flaws, 8 more outside the taxonomy) were written and committed
before the scanner was run (`150fec2`). vulnerable-node ships a `sast/seeds/` directory of labelled
vulnerable and clean files, which supplied 20 of the flaws and two clean-file negatives.

| | Planted | Found, scanner as it was | Found after fixes |
|---|---|---|---|
| VAmPI (Flask / connexion) | 7 | 1 | 4 |
| dvpwa (aiohttp) | 4 | 1 | 4 |
| nodejs-goof (Express) | 6 | 3 | 4 |
| vulnerable-node (Express) | 35 | 16 | 27 |
| dvws-node (Express) | 12 | 5 | 12 |
| **Total** | **64** | **26 (41%)** | **52 (81%, tuned-on)** |

**Untouched recall: 41%** -- the third untouched measurement (52%, 49%, 41%). Across all twelve
applications and 153 planted flaws the scanner as first run found about half; after fixes made on those
applications it finds 88% (135/153).

What the misses were: spec-first (connexion) handlers named only in an OpenAPI document; SQL assembled
from function arguments rather than request fields (no taint source in the file); NoSQL filters built in a
variable one line earlier; `new User(req.body)`; secrets in logs; zip extraction; `res.location`;
`xpath.evaluate` and `noent: true` split across lines; `app.config['SECRET_KEY'] = 'random'`;
`web.Application(debug=True)`; `setup_jinja(autoescape=False)`.

Costs: structural SQL/NoSQL rules fire without a request source, so volume rises (nodejs-goof 23 -> 31
findings, vulnerable-node 39 -> 54). Of 11 unlisted findings of those classes, 3 look false (a `$where`
over a constant, a lab slug path, a public product lookup). The benchmark stayed at 97% precision
and rose to 97% recall; the two clean seed files reported two false positives before a validated-redirect
and escaped-output check, and none after.

Still missed: Mongoose `User.find({password: req.body.password})`-style bodies through helpers,
`findById`-by-title BOLA in spec-first handlers (VAmPI), mass assignment of an alias (`const fields =
req.body`), `fetch(url)` in a helper, template placeholders, `readFileSync(join(base, user))`.

## Human labelling sheet

`python -m app.evaluation html labels.json --out sheet.html` writes a self-contained page (no server, no
network) for a person to label a sample in a browser: each finding shows its code excerpt, a one-line
question for its type, and Real / Not real / Unsure buttons plus a note. Choices persist in the browser;
**Download labels.json** writes a file that `python -m app.evaluation score` accepts, with `labelled_by`
set to the reviewer's name. A 49-finding sample (at most 3 per type, shuffled) was prepared from the five
third-set applications for this purpose.
