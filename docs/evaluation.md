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

## Fourth untouched set: lets-be-bad-guys, django.nV, Tiredful-API, vulnpy (2026-10-13)

Lists of 54 in-taxonomy planted flaws were written and committed before scoring (`48db15c`). **No detector
was changed for this set**: this is a pure measurement of the scanner after ADR-025.

| Application | Planted | Found | Notes |
|---|---|---|---|
| lets-be-bad-guys (Django) | 8 | 5 | missed: dict-backed IDOR, two template-level XSS |
| django.nV (Django) | 17 | 5 | **0 of 11 IDORs**; `MD5PasswordHasher` setting |
| Tiredful-API (DRF) | 5 | 5 | all found |
| vulnpy (sink library) | 24 | 10 | sinks fed by function parameters |
| **Total** | **54** | **25 (46%)** | untouched |

Four untouched measurements of planted-flaw recall: **52%, 49%, 41%, 46%** (pooled 96/207 = 46%). The
repeated result is the headline: *an application the scanner has not been tuned on yields roughly 45%
of its planted flaws.* After fixes tuned on the earlier sets, the same scanner reaches 160/207 (77%) over
all 207 planted flaws (not independent).

### Why the two weakest apps were missed
- **Django function views are not handlers.** django.nV's views are plain `def view(request, ...)` wired
  in `urls.py`; no decorator marks them, so the access-control and taint analysers never treat them as
  request handlers and report none of 11 annotated IDORs. This is the same class of gap the OpenAPI work
  closed for connexion, and it is the single largest systematic miss left.
- **Sinks fed by parameters, not requests.** vulnpy's flaws sit in helper functions (`def
  do_open(user_input): open(user_input)`); with no request source in the file only the structural rules
  fire. Not covered: `open(param)`, `tarfile.open(param)`, `yaml.load(x, Loader=UnsafeLoader)`,
  `compile(code)`, `hashlib.new("SHA1")`, `pulldom.parseString`, `findall(param)`, and
  `SQL = FMT.format(param)` with the format string defined at module level.
- Settings-only flaws (`MD5PasswordHasher`) and template-level XSS (`|safe`) are invisible.

### Limits
Same as earlier sets: truth lists are one reader's, partly the projects' own `# A4:` markers. vulnpy is a
sink library, so its density and structure are unlike application code.

### Follow-up: Django `urls.py` handlers (ADR-027)

The one systematic gap the fourth set exposed was fixed: `urls.py` entries (`url(...)`, `path(...)`,
`re_path(...)`, string views) now name the plain function views that analysers treat as handlers
(`include(...)` and `.as_view()` are skipped). A literal same-site path prefix (`redirect('/app/' + id)`)
is no longer reported as an open redirect.

| | Before | After |
|---|---|---|
| django.nV planted flaws found | 5 / 17 | **15 / 17** (10 of 11 IDORs) |
| django.nV findings reported | 18 | 36 |
| All 207 planted flaws | 160 (77%) | 170 (82%) |

Honest reading: **the 46% fourth-set number is unchanged** (it was measured before this fix); 82% over
all 207 is tuned-on. The fix is general to Django projects that wire function views through `urls.py`,
so it should help unseen Django code, but that is not yet measured -- a fifth untouched set is needed.
Missed: `MD5PasswordHasher` in settings and one IDOR whose lookup is split from the view.

## Fifth untouched set: Pixi, DVSA, crAPI (2026-10-13)

Lists of 19 in-taxonomy planted flaws were committed before scoring (`784f091`); the scanner was the
post-ADR-027 version, **unchanged for this set**. The set is small and was chosen to test the earlier
fixes on unseen code (Express API, serverless Node/Python, Django REST).

| Application | Planted | Found | Missed |
|---|---|---|---|
| Pixi (Express + Mongo) | 8 | 4 | Mongo operator injection in login, two `is_admin` mass assignments, a log line with the password |
| DVSA (serverless) | 7 | 5 | the `eval`s in the Python lambda and a `/tmp/` + file path |
| crAPI workshop (Django REST) | 4 | 2 | status mass assignment, mechanic-report BOLA (class-based views) |
| **Total** | **19** | **11 (58%)** | |

Five untouched measurements: **52%, 49%, 41%, 46%, 58%; pooled 107/226 = 47%.** Every untouched set
lands between 41% and 58%; the best prediction for an unseen vulnerable application remains "about
half".

Noise to know about: Pixi reports 108 findings (71 in a single proxy `server.js`, mostly
"unguarded route" and structural NoSQL), crAPI 132 (58 are `sensitive_data_in_log` in a chatbot service).
The new structural rules and the volume of "unguarded" reports make the *count* of findings a poor
proxy for risk on API-heavy projects; triage by type and severity.

## Sixth untouched set: skf-labs (Python), DVGA, Damn-Vulnerable-RESTaurant (2026-10-13)

57 in-taxonomy planted flaws were committed before scoring (`9cb3618`); the scanner was the post-ADR-028
version, **unchanged**. The truth list is one reader's (mine, a model), built from the labs' own intent.

| Application | Planted | Found | Missed |
|---|---|---|---|
| skf-labs python labs (~65 tiny Flask apps) | 47 | 35 | LFI-2/3 (`open_resource`), `text("..." + x)` in graphql lab, `pulldom.parseString`, `send_from_directory` IDOR, 5 template-level XSS / `Markup`, `app.secret_key` inside `__main__`, Mongo `find_one` with request JSON |
| DVGA (Flask + graphene) | 7 | 1 | GraphQL resolver arguments are not request sources: 3 command injections, 1 SQL, 1 path, plus `app.config['SECRET_KEY'] = 'dvga'` |
| Damn-Vulnerable-RESTaurant (FastAPI) | 3 | 3 | none |
| **Total** | **57** | **39 (68%)** | |

Six untouched measurements: **52%, 49%, 41%, 46%, 58%, 68%; pooled 146/283 = 52%.** Over all 283 planted
flaws incl. tuned-on ones: 220 (78%).

Reading it honestly: 68% is the highest so far, but the set is **easy by construction**. skf-labs are
single-file, one-flaw-per-file apps with the sink next to the request read, and 10 of the 35 hits are
hard-coded `SECRET_KEY` literals. Excluding secrets the rate is 29/46 (63%). The real-application result in
the set (DVGA) is 1/7, which matches earlier sets: framework-mediated input (GraphQL resolver arguments)
is the blind spot, not simple Flask code.

Gaps recorded (not fixed here): GraphQL/graphene resolver arguments as sources; `Markup()` and
template-level XSS; `app.secret_key = "..."` in a `__main__` block and `config['SECRET_KEY']` with a
short word; `text("..." + x)` as a statement argument; `current_app.open_resource`; `pulldom`.

## Seventh untouched set: Vulnerable-Flask-App (videvelopers), ivna, vulnerable-app-nodejs-express (2026-10-14)

16 in-taxonomy planted flaws were committed before scoring (`3cd70d2`); the scanner was the post-ADR-029
version, **unchanged**. All three are small, real GitHub projects (not single-vuln labs).

| Application | Planted | Found | Missed |
|---|---|---|---|
| Vulnerable-Flask-App (videvelopers, Python) | 6 | 6 | none |
| ivna (Node/Express/Mongoose) | 7 | 5 | `needle.get(query.url)` SSRF and the `res.redirect(query.url)` right after it (both read the URL from a hand-parsed `url.parse(req.url, true).query`, not `req.query`) |
| vulnerable-app-nodejs-express (Express/pg) | 3 | 1 | `` res.send(`Hello, ${req.query.name}`) `` reflected XSS and a template-literal SQL string built from `req.params.id`, both one-line files with no other taint context |
| **Total** | **16** | **12 (75%)** | |

Seven untouched measurements: **52%, 49%, 41%, 46%, 58%, 68%, 75%; pooled 158/299 = 53%.** The two misses
worth generalising: a URL taken from `url.parse(req.url, true).query` instead of `req.query`/`req.body`,
and an SQL/XSS sink built with a JS template literal (`` `...${x}` ``) that is also a `res.send`/`client.query`
single-expression return rather than an assignment first. Both are narrow aliasing gaps in the JS taint
pass, not a new class of miss.
