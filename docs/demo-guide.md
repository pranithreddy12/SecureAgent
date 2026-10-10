# SecureAgent – Demo Guide

A ready-to-present demonstration that needs **no external services, credentials, database,
LLM key, or network access**.

## What the demo is (and is not)

`secureagent demo` runs the **real SecureAgent static-analysis engine** against a small,
**deliberately vulnerable** sample application bundled with the package
(`backend/app/demo/demo_fixtures/vulnerable_shop/`).

| Real | Not real |
|---|---|
| The analysis engine, every detector, the CWE/OWASP mapping, the report generator | The *application being scanned* — "Vulnerable Shop" is a fake app written to contain flaws |
| Every finding is a genuine detection on that code | The credentials in `config.py` are fake placeholders (the AWS key is the example from AWS's own documentation) |

Because the subject is fake, every demo report is stamped **DEMO / SIMULATED SECURITY
AUDIT** and states that it does not describe a real system. Demo output is never to be
presented as the result of auditing a real system.

> This is the demo for the **static-analysis engine**. The fixture-driven demo of the
> multi-agent *live* audit pipeline (recon → ZAP/Nuclei → validation) described in the
> specification is not built yet, because that pipeline depends on target management
> (see [target-management-implementation.md](target-management-implementation.md)).

## Run it

```bash
cd backend
python -m app.cli demo                       # or, once installed:  secureagent demo
python -m app.cli demo --report demo.html    # professional HTML report (labelled DEMO)
python -m app.cli demo --pdf demo.pdf        # PDF (needs the WeasyPrint libraries; Docker has them)
python -m app.cli demo --online              # also look up the sample's pinned dependencies in OSV
```

Offline by default. The dependency check is the only part that needs the network, so it is
reported honestly as skipped unless you pass `--online`.

## What you will see (34 findings, offline)

| Class | Planted flaw | Reported as |
|---|---|---|
| Injection (data-flow) | String-built SQL query from `request.args` | SQL injection, CWE-89 |
| | `subprocess(..., shell=True)` with user input | Command injection, CWE-78 |
| | `requests.get(<user url>)` | SSRF, CWE-918 |
| | `open("/srv/files/" + name)` | Path traversal, CWE-22 |
| | `eval(... + current_theme())` — input arrives through a **helper's return value** | Code injection, CWE-95 (critical) |
| | Node: template-literal SQL, `res.redirect(req.query.next)` | SQL injection; open redirect, CWE-601 |
| Access control | `Order.query.get_or_404(order_id)` with no ownership check | IDOR, CWE-639 |
| | `POST /admin/delete_user`, `POST /admin/reset` with no auth | Missing authorization, CWE-862 |
| Sinks | `pickle.loads(request.data)`, `verify=False`, `hashlib.md5` | CWE-502, CWE-295, CWE-327 |
| Misconfiguration | `DEBUG=True`, CSRF off, wildcard CORS **with credentials**, JWT `verify_signature: False` | CWE-489, 352, 942, 347 |
| Business logic | `User(**request.json)`; `user.is_admin = request.json[...]`; `charge(amount=request.json[...])` | Mass assignment CWE-915; client-trusted privilege CWE-269; client-trusted value CWE-602 |
| Declared intent | `secureagent-intent.json` says `/admin/*` needs auth and `/orders/*` is owner-scoped | Rule violations (CWE-862 / CWE-639) |
| Logging | Password written to a log; `except: pass` | CWE-532, CWE-778 |
| Secrets | AWS key, two high-entropy credentials (redacted: `AK••••••••••LE (len 20)`) | CWE-798 |

## Just as important: what it does **not** report

- **`safe_routes.py`** contains the *correct* versions of the same operations (parameterised
  SQL, an argument-list subprocess, an ownership-scoped lookup, SHA-256, `yaml.safe_load`,
  a server-side price lookup).
  SecureAgent reports **nothing** there — it tells vulnerable code from correct code.
- `SECRET_KEY = "load-me-from-the-environment"` is a placeholder and is correctly ignored.
- `app.get('/account', requireAuth, ...)` is protected and is correctly ignored.

## Suggested 5-minute walkthrough

1. **Frame it (30 s).** "SecureAgent audits an application's own source. This sample app is
   fake and intentionally broken; the engine analysing it is the real one."
2. **Run `secureagent demo` (1 min).** Point out the DEMO banner, the totals by severity, and
   that findings are grouped by class with CWE numbers.
3. **Show depth (1.5 min).** Open `app.py` beside the output: the code-injection finding is the
   only one where the dangerous call (`eval`) is *not* next to the user input — the input comes
   through `current_theme()`'s return value. A pattern-matching linter cannot see that.
4. **Show restraint (1 min).** Show `safe_routes.py` producing zero findings, and the redacted
   secret values.
5. **Show honesty (30 s).** Statuses are `likely` / `suspicious`, never `confirmed`, and
   unprotected-endpoint findings say "may be globally guarded".
6. **Show the deliverable (30 s).** `secureagent demo --report demo.html`, open it: the
   executive summary, CWE/OWASP tables and remediation per finding.

## Maintaining it

`backend/tests/test_demo.py` pins the demo: every planted flaw class must still be found,
`safe_routes.py` must stay clean, the placeholder must stay ignored, the provider key must be
reported once, no finding may be `confirmed`, and the report must carry the DEMO label.
If you change a detector and this test fails, the demonstration would have regressed.

The fixtures live in a directory named `demo_fixtures`, which ordinary scans skip — so
`secureagent scan` over this repository never reports the intentional flaws — and which
`ruff` excludes from linting.
