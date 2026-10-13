"""Detectors added after the vulnerable-app evaluation (ADR-023): each case pairs the planted flaw
with the nearest safe form that must stay quiet."""

from __future__ import annotations

import textwrap

from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint, analyze_taint_project


def src(text: str) -> str:
    return textwrap.dedent(text)


def py_types(code: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("app.py", src(code))}


def js_types(code: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint_project([("app.js", src(code))])}


def sink_cats(path: str, code: str) -> list[str]:
    return [f.category for f in scan_sinks(path, src(code))]


# ------------------------------------------------------------------ template injection


def test_server_side_template_injection():
    bad = """
        @app.route("/hello")
        def hello():
            name = request.args["name"]
            return render_template_string("<h1>Hello " + name + "</h1>")
    """
    assert "template_injection" in py_types(bad)
    good = """
        @app.route("/hello")
        def hello():
            name = request.args["name"]
            return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
    """
    assert "template_injection" not in py_types(good)


def test_format_on_an_attacker_supplied_template():
    bad = """
        @app.route("/t")
        def t():
            tmpl = request.args["tmpl"]
            return tmpl.format(os)
    """
    assert "template_injection" in py_types(bad)
    good = """
        @app.route("/t")
        def t():
            return "Hello {}".format(request.args["name"])
    """
    assert "template_injection" not in py_types(good)


# ------------------------------------------------------------------ XPath


def test_xpath_injection():
    bad = """
        @app.route("/u")
        def u():
            name = request.args["name"]
            return tree.xpath(".//user[name/text()='%s']" % name)
    """
    assert "xpath_injection" in py_types(bad)
    good = """
        @app.route("/u")
        def u():
            name = request.args["name"]
            return tree.xpath(".//user[name/text()=$n]", n=name)
    """
    assert "xpath_injection" not in py_types(good)


# ------------------------------------------------------------------ NoSQL


def test_nosql_operator_and_where_injection():
    whole = """
        @app.route("/find", methods=["POST"])
        def find():
            return list(db.users.find(request.json))
    """
    assert "nosql_injection" in py_types(whole)
    where = """
        @app.route("/w")
        def w():
            return list(db.users.find({"$where": "this.age > " + request.args["a"]}))
    """
    assert "nosql_injection" in py_types(where)
    fixed = """
        @app.route("/f")
        def f():
            return list(db.users.find({"name": str(request.args["n"])}))
    """
    assert "nosql_injection" not in py_types(fixed)


def test_js_nosql_where_and_whole_object():
    where = "const q = { $where: `this.userId == ${uid} && this.stocks > ${t}` };\n"
    assert "nosql_injection" in js_types(where)
    whole = "app.post('/f', (req, res) => { users.find(req.body, cb); });\n"
    assert "nosql_injection" in js_types(whole)
    safe = "const q = { $where: 'this.stocks > 5' };\n"
    assert "nosql_injection" not in js_types(safe)


# ------------------------------------------------------------------ reflected XSS


def test_reflected_xss_in_a_returned_html_string():
    bad = """
        @app.route("/greet")
        def greet():
            name = request.args["name"]
            return "<h1>Hello " + name + "</h1>"
    """
    assert "reflected_xss" in py_types(bad)
    fstring = """
        @app.route("/greet")
        def greet():
            return f"<p>{request.args['q']}</p>"
    """
    assert "reflected_xss" in py_types(fstring)
    escaped = """
        @app.route("/greet")
        def greet():
            name = request.args["name"]
            return "<h1>Hello " + escape(name) + "</h1>"
    """
    assert "reflected_xss" not in py_types(escaped)
    plain = """
        @app.route("/greet")
        def greet():
            return "Hello " + request.args["name"]
    """
    assert "reflected_xss" not in py_types(plain)  # no markup in the response


# ------------------------------------------------------------------ session cookie


def test_unsigned_session_cookie():
    bad = """
        import base64, json
        def create(response, username):
            session = base64.b64encode(json.dumps({"username": username}).encode())
            response.set_cookie("app_session", session)
            return response
    """
    assert "insecure_session_cookie" in sink_cats("a.py", bad)
    signed = """
        def create(response, username):
            token = serializer.dumps({"username": username})
            response.set_cookie("app_session", token)
            return response
    """
    assert "insecure_session_cookie" not in sink_cats("a.py", signed)
    other = """
        def theme(response):
            response.set_cookie("theme", "dark")
            return response
    """
    assert "insecure_session_cookie" not in sink_cats("a.py", other)


# ------------------------------------------------------------------ plaintext passwords


def test_password_stored_or_inserted_without_hashing():
    insert = """
        def create(username, password):
            q = "INSERT INTO users (username, password) VALUES ('%s', '%s')"
            c.execute(q % (username, password))
    """
    assert "plaintext_password" in sink_cats("a.py", insert)
    model = """
        def register(username, password):
            user = User(username, password)
            db.session.add(user)
    """
    assert "plaintext_password" in sink_cats("a.py", model)
    attr = """
        def set_pw(user, password):
            user.password = password
    """
    assert "plaintext_password" in sink_cats("a.py", attr)


def test_hashed_passwords_are_not_reported():
    hashed = """
        def create(username, password):
            pw = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, pw))
    """
    assert "plaintext_password" not in sink_cats("a.py", hashed)
    unrelated = """
        def login(username, password):
            return check(username, password)
    """
    assert "plaintext_password" not in sink_cats("a.py", unrelated)


# ------------------------------------------------------------------ JavaScript IDOR


def test_js_record_fetched_by_request_id_without_owner_scope():
    bad = """
        module.exports.edit = function (req, res) {
          db.User.find({
            where: {
              'id': req.body.id
            }
          }).then(user => { user.name = req.body.name; user.save(); });
        };
    """
    assert "idor" in js_types(bad)
    scoped = """
        module.exports.edit = function (req, res) {
          db.User.find({ where: { id: req.body.id, tenantId: req.user.tenantId } });
        };
    """
    assert "idor" not in js_types(scoped)
    own = """
        module.exports.me = function (req, res) {
          db.User.find({ where: { id: req.session.userId } });
        };
    """
    assert "idor" not in js_types(own)
