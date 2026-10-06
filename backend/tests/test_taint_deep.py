"""Tests for interprocedural Python taint and JS/TS taint (deepening, #1)."""

from __future__ import annotations

from app.analysis.taint import analyze_taint


def ptypes(src: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("m.py", src)}


def jtypes(src: str, name: str = "a.js") -> set[str]:
    return {f.vuln_type for f in analyze_taint(name, src)}


INTERPROC = """
from flask import request
import os

def run_cmd(c):
    os.system(c)                 # sink is here, input comes from the handler

@app.route("/ping")
def ping():
    host = request.args.get("host")
    run_cmd("ping " + host)
"""

INTERPROC_TWO_HOPS = """
from flask import request
import os

def really_run(x):
    os.system(x)

def run_cmd(c):
    really_run(c)

@app.route("/ping")
def ping():
    run_cmd(request.args.get("host"))
"""

INTERPROC_SAFE = """
import os

def run_cmd(c):
    os.system(c)

@app.route("/ping")
def ping():
    run_cmd("ping localhost")    # constant arg -> callee not tainted
"""


def test_interprocedural_one_hop() -> None:
    findings = analyze_taint("m.py", INTERPROC)
    assert any(f.vuln_type == "command_injection" for f in findings)
    # Reported at the sink's actual line (inside run_cmd).
    cmd = next(f for f in findings if f.vuln_type == "command_injection")
    assert cmd.line == 6


def test_interprocedural_two_hops() -> None:
    assert "command_injection" in ptypes(INTERPROC_TWO_HOPS)


def test_interprocedural_constant_arg_safe() -> None:
    assert "command_injection" not in ptypes(INTERPROC_SAFE)


def test_no_duplicate_when_helper_called_twice() -> None:
    src = (
        "from flask import request\nimport os\n"
        "def run_cmd(c):\n    os.system(c)\n"
        "@app.route('/a')\ndef a():\n    run_cmd(request.args.get('x'))\n"
        "@app.route('/b')\ndef b():\n    run_cmd(request.args.get('y'))\n"
    )
    findings = [f for f in analyze_taint("m.py", src) if f.vuln_type == "command_injection"]
    assert len(findings) == 1  # one sink line, deduplicated across callers


def test_js_sql_injection() -> None:
    src = "const id = req.query.id;\ndb.query(`SELECT * FROM t WHERE id=${id}`);\n"
    assert "sql_injection" in jtypes(src)


def test_js_command_and_eval() -> None:
    assert "command_injection" in jtypes("const c = req.body.cmd;\nchild_process.exec(c);\n")
    assert "code_injection" in jtypes("app.get('/x', (req,res)=>{ eval(req.query.e); });\n")


def test_js_destructured_source() -> None:
    src = "const { url } = req.query;\naxios(url);\n"
    assert "ssrf" in jtypes(src)


def test_js_open_redirect() -> None:
    assert "open_redirect" in jtypes(
        "app.get('/r',(req,res)=>{ res.redirect(req.query.next); });\n"
    )


def test_js_path_traversal() -> None:
    src = "const p = req.params.file;\nfs.readFile('/data/'+p, cb);\n"
    assert "path_traversal" in jtypes(src)


def test_js_no_source_no_finding() -> None:
    assert jtypes("db.query('SELECT 1');\nchild_process.exec('ls');\n") == set()


def test_ts_extension_supported() -> None:
    src = "const id = req.params.id;\ndb.execute(`DELETE FROM t WHERE id=${id}`);\n"
    assert "sql_injection" in jtypes(src, "handler.ts")
