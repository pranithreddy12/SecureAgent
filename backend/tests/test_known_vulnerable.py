"""Behaviours added after scoring the scanner against intentionally vulnerable applications
(DSVW, vulpy, Vulnerable-Flask-App, dvna, NodeGoat), plus the recall-scoring command itself."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from app.analysis.secrets import scan_text
from app.analysis.sinks import scan_sinks
from app.analysis.taint import analyze_taint, analyze_taint_project
from app.evaluation import known_recall


def src(text: str) -> str:
    return textwrap.dedent(text)


def types(findings) -> set[str]:
    return {f.vuln_type for f in findings}


# ------------------------------------------------------------------ http.server handlers

HANDLER = """
    import sqlite3, subprocess
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            path, query = self.path.split('?', 1) if '?' in self.path else (self.path, "")
            params = dict(p.split('=') for p in query.split('&') if '=' in p)
            cur = connection.cursor()
            cur.execute("SELECT * FROM users WHERE id=" + params["id"])
            self.send_header("Location", params["redir"])
"""


def test_basehttprequesthandler_path_is_request_input():
    found = types(analyze_taint("srv.py", src(HANDLER)))
    assert {"sql_injection", "open_redirect"} <= found


def test_attribute_named_path_outside_a_handler_is_not_a_source():
    text = """
        class Store:
            def load(self):
                p = self.path
                return open(p)
    """
    assert types(analyze_taint("a.py", src(text))) == set()
    fixed = """
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_header("Location", "/home")
    """
    assert types(analyze_taint("a.py", src(fixed))) == set()


# --------------------------------------------- XML of the program's own literal


def test_xml_parse_of_a_module_constant_is_not_reported_but_input_is():
    constant = (
        "import xml.etree.ElementTree as ET\n"
        'DOC = "<users><user/></users>"\n'
        "def users():\n"
        "    return ET.fromstring(DOC)\n"
    )
    assert [f for f in scan_sinks("a.py", constant) if f.category.startswith("xml")] == []
    from_input = (
        "import xml.etree.ElementTree as ET\ndef users(data):\n    return ET.fromstring(data)\n"
    )
    assert [f for f in scan_sinks("a.py", from_input) if f.category.startswith("xml")]
    rebound = (
        "import xml.etree.ElementTree as ET\n"
        'DOC = "<a/>"\n'
        "def users(data):\n"
        "    global DOC\n"
        "    DOC = data\n"
        "    return ET.fromstring(DOC)\n"
    )
    assert [f for f in scan_sinks("a.py", rebound) if f.category.startswith("xml")]


# ------------------------------------------------------------------ JavaScript


def js(text: str):
    return analyze_taint_project([("app.js", src(text))])


def test_js_query_built_on_an_earlier_line_is_sql_injection():
    built = """
        exports.search = function (req, res) {
          var query = "SELECT * FROM Users WHERE login='" + req.body.login + "'";
          db.sequelize.query(query, { model: db.User }).then(done);
        };
    """
    assert "sql_injection" in types(js(built))
    parameterised = """
        exports.search = function (req, res) {
          var login = req.body.login;
          db.sequelize.query("SELECT * FROM Users WHERE login = ?", { replacements: [login] });
        };
    """
    assert "sql_injection" not in types(js(parameterised))


def test_js_ssrf_client_libraries_and_uploaded_file_sources():
    ssrf = """
        app.get('/research', (req, res) => {
          const url = req.query.url + req.query.symbol;
          needle.get(url, (err, r, body) => res.send(body));
        });
    """
    assert "ssrf" in types(js(ssrf))
    got = "app.get('/p', (req, res) => { const u = req.query.u; axios.get(u); });\n"
    assert "ssrf" in types(js(got))


def test_js_node_serialize_and_libxmljs_noent_are_reported():
    deser = "var p = serialize.unserialize(req.files.products.data.toString('utf8'));\n"
    assert [f for f in scan_sinks("a.js", deser) if f.category == "insecure_deserialization"]
    xxe = "var doc = libxmljs.parseXmlString(data, {noent:true,noblanks:true});\n"
    assert [f for f in scan_sinks("a.js", xxe) if f.category == "xxe"]
    safe = "var doc = libxmljs.parseXmlString(data, {noent:false});\n"
    assert [f for f in scan_sinks("a.js", safe) if f.category == "xxe"] == []


# ------------------------------------------------------------------ secrets / ingest


def test_secret_named_key_with_a_placeholder_style_value_is_low_not_ignored():
    found = scan_text("config/env/all.js", '    cookieSecret: "session_cookie_secret_key_here",\n')
    assert [(f.rule, f.severity) for f in found] == [
        ("Hardcoded placeholder-style credential (cookieSecret)", "low")
    ]
    # a descriptive or enum-like key is still not a secret
    assert scan_text("a.py", 'TOKEN_TRANSFER = "token_transfer"\n') == []


def test_config_env_directory_is_scanned_but_a_virtualenv_is_not(tmp_path: Path):
    from app.analysis.ingest import iter_source_files

    (tmp_path / "config" / "env").mkdir(parents=True)
    (tmp_path / "config" / "env" / "dev.js").write_text("module.exports = {}\n", encoding="utf-8")
    venv = tmp_path / "env"
    (venv / "lib").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr\n", encoding="utf-8")
    (venv / "lib" / "site.py").write_text("x = 1\n", encoding="utf-8")
    names = sorted(f.relpath for f in iter_source_files(tmp_path))
    assert names == ["config/env/dev.js"]


# ------------------------------------------------------------------ the recall command


def test_known_recall_counts_found_missed_and_outside_taxonomy(tmp_path: Path):
    apps = tmp_path / "apps"
    app = apps / "demo"
    app.mkdir(parents=True)
    (app / "a.py").write_text(
        "import hashlib, pickle\n"
        "def f(x):\n"
        "    return hashlib.md5(x).hexdigest()\n"
        "def g(blob):\n"
        "    return pickle.loads(blob)\n",
        encoding="utf-8",
    )
    truth = tmp_path / "truth.json"
    truth.write_text(
        json.dumps(
            {
                "repos": {
                    "demo": {
                        "known": [
                            {"file": "a.py", "line": 3, "class": "weak_hash"},
                            {"file": "a.py", "line": 5, "class": "deserialization"},
                            {"file": "a.py", "line": 40, "class": "sql_injection"},
                            {"file": "a.py", "line": 1, "class": "ssti", "in_taxonomy": False},
                        ]
                    },
                    "absent": {"known": []},
                }
            }
        ),
        encoding="utf-8",
    )
    result = known_recall(str(truth), str(apps))
    assert (result["found"], result["missed"], result["outside"]) == (2, 1, 1)
    assert abs(result["recall"] - 2 / 3) < 1e-9
    assert "error" in result["repos"]["absent"]


def test_bundled_truth_file_is_well_formed():
    path = Path(__file__).resolve().parent.parent / "benchmark" / "known_vulnerable.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    for name, spec in data["repos"].items():
        assert spec["commit"] and spec["known"], name
        for k in spec["known"]:
            assert k["file"] and isinstance(k["line"], int) and k["class"], (name, k)


# ------------------------------------------------------------------ in-handler session guards


def test_session_gate_and_authenticate_call_are_in_handler_guards():
    from app.analysis.routes import extract_routes, route_findings

    def unguarded(code: str) -> list:
        return route_findings(extract_routes("m.py", src(code)))

    gated = """
        @bp.route('/', methods=['POST'])
        def create():
            if 'username' not in g.session:
                return redirect('/user/login')
            return do()
    """
    assert unguarded(gated) == []
    api_key = """
        @bp.route('/post', methods=['POST'])
        def create():
            username = libapi.authenticate(request)
            if not username:
                return jsonify({'error': 'no'}), 401
            return 'ok'
    """
    assert unguarded(api_key) == []
    not_a_gate = """
        @bp.route('/post', methods=['POST'])
        def create():
            if 'x' not in request.args:
                return 'bad request'
            return 'ok'
    """
    assert unguarded(not_a_gate)
