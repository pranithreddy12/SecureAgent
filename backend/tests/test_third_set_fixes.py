"""Fixes after the third held-out set (VAmPI, dvpwa, nodejs-goof, vulnerable-node, dvws-node)."""

from __future__ import annotations

import textwrap

from app.analysis.misconfig import scan_misconfig
from app.analysis.openapi_spec import locate_handler, parse_spec
from app.analysis.secrets import scan_text
from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint_project


def js(code: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint_project([("app.js", textwrap.dedent(code))])}


def test_python_sql_built_by_formatting_but_not_numeric_casts():
    bad = "def f(name):\n    q = f\"SELECT * FROM users WHERE n = '{name}'\"\n    db.execute(text(q))\n"  # noqa: E501
    assert "sql_injection" in {f.category for f in scan_sinks("a.py", bad)}
    cast = (
        'def f(x):\n    uid = int(x)\n    cur.execute("SELECT * FROM t WHERE id = " + str(uid))\n'
    )
    assert "sql_injection" not in {f.category for f in scan_sinks("a.py", cast)}
    bound = 'def f(name):\n    cur.execute("SELECT * FROM t WHERE n = %s", (name,))\n'
    assert "sql_injection" not in {f.category for f in scan_sinks("a.py", bound)}


def test_generalised_debug_and_autoescape_keywords():
    code = "app = web.Application(debug=True)\nsetup_jinja(app, autoescape=False)\n"
    cats = {f.category for f in scan_misconfig("a.py", code)}
    assert {"debug_enabled", "template_autoescape_off"} <= cats


def test_config_subscript_secret_and_express_session_secret():
    assert scan_text("config.py", "app.config['SECRET_KEY'] = 'random'\n")
    session = (
        "const session = require('express-session')\napp.use(session({ secret: 'keyboard cat' }))\n"
    )
    assert scan_text("app.js", session)


def test_js_structural_rules():
    assert "sql_injection" in js(
        'function q(u) {\n  return pool.query("SELECT * FROM users WHERE n = \'" + u + "\'");\n}\n'
    )
    assert "sql_injection" not in js(
        'app.get("/x", (req, res) => { res.send("SELECT is a word"); });\n'
    )
    assert "mass_assignment" in js("const u = new User(req.body);\n")
    assert "nosql_injection" in js(
        "const filter = { name: req.query.name };\nconst docs = await col.find(filter).toArray();\n"
    )
    assert "sensitive_data_in_log" in js("console.log(`login password=${password}`);\n")
    assert "reflected_xss" in js(
        "app.get('/g', (req, res) => { res.send('<h1>' + req.query.n); });\n"
    )


def test_js_validated_redirect_and_escaped_output_stay_quiet():
    ok = (
        "app.get('/r', (req, res) => {\n"
        "  const next = req.query.u || '/';\n"
        "  if (!next.startsWith('/') || next.startsWith('//')) { return res.redirect('/'); }\n"
        "  res.redirect(next);\n"
        "});\n"
        "app.get('/g', (req, res) => { res.send('<h1>' + escapeHtml(req.query.n) + '</h1>'); });\n"
    )
    found = js(ok)
    assert "open_redirect" not in found and "reflected_xss" not in found


def test_new_function_with_a_dynamic_body_is_not_a_constant_call():
    bad = "const f = new Function('name', 'return ' + req.params.name);\n"
    assert "code_injection" in js(bad)


def test_openapi_operations_and_security():
    spec = (
        "openapi: 3.0.0\nsecurity:\n  - bearerAuth: []\npaths:\n"
        "  /users/v1/_debug:\n    get:\n      operationId: api_views.users.debug\n      security: []\n"  # noqa: E501
        "  /users/v1/me:\n    get:\n      operationId: api_views.users.me\n"
    )
    ops = {o.function: o for o in parse_spec("openapi_specs/openapi3.yml", spec)}
    assert ops["debug"].secured is False and ops["me"].secured is True
    where = locate_handler(
        ops["debug"], [("api_views/users.py", "x = 1\ndef debug():\n    pass\n")]
    )
    assert where == ("api_views/users.py", 2)
