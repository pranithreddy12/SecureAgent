"""Tests for lightweight taint analysis (batch #2)."""

from __future__ import annotations

from pathlib import Path

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.taint import analyze_taint
from app.models.enums import FindingStatus
from app.reports.renderer import render_html


def types(src: str) -> set[str]:
    return {f.vuln_type for f in analyze_taint("m.py", src)}


SQLI = """
from flask import request
import db
@app.route("/u")
def handler():
    name = request.args.get("name")
    q = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.cursor().execute(q)
"""

SQLI_PARAMETERIZED = """
from flask import request
import db
@app.route("/u")
def handler():
    name = request.args.get("name")
    return db.cursor().execute("SELECT * FROM users WHERE name = %s", [name])
"""

CMDI = """
from flask import request
import os
@app.route("/ping")
def handler():
    host = request.args.get("host")
    os.system("ping " + host)
"""

SSRF = """
import requests
@app.get("/fetch")
def handler(url: str):
    return requests.get(url)
"""

PATH = """
from flask import request
@app.route("/f")
def handler():
    p = request.args.get("p")
    return open("/data/" + p).read()
"""

CODEI = """
from flask import request
@app.route("/calc")
def handler():
    expr = request.args.get("e")
    return eval(expr)
"""


def test_sql_injection_flagged() -> None:
    assert "sql_injection" in types(SQLI)


def test_parameterized_query_is_safe() -> None:
    # The query string is constant; only the parameter is tainted -> NOT flagged.
    assert "sql_injection" not in types(SQLI_PARAMETERIZED)


def test_command_injection_flagged() -> None:
    assert "command_injection" in types(CMDI)


def test_ssrf_from_handler_param() -> None:
    assert "ssrf" in types(SSRF)


def test_path_traversal_flagged() -> None:
    assert "path_traversal" in types(PATH)


def test_code_injection_flagged() -> None:
    assert "code_injection" in types(CODEI)


def test_constant_sink_not_flagged() -> None:
    src = "import os\n@app.route('/x')\ndef h():\n    os.system('ls -l')\n"
    assert analyze_taint("m.py", src) == []


def test_non_handler_without_source_not_flagged() -> None:
    # A plain helper whose params are not request input, no request.* used.
    src = "import os\ndef helper(cmd):\n    os.system(cmd)\n"
    assert analyze_taint("m.py", src) == []


def test_injected_dependency_param_not_tainted() -> None:
    # A Depends()-injected param is a service, not raw input.
    src = (
        "from fastapi import Depends\n"
        "@router.get('/x')\n"
        "def h(db=Depends(get_db)):\n"
        "    return db.execute(db)\n"
    )
    assert "sql_injection" not in types(src)


def test_syntax_error_safe() -> None:
    assert analyze_taint("m.py", "def (:\n") == []


def test_taint_findings_in_scan_and_report(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(SQLI, encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert result.taint_findings
    ctx = scan_to_report_context(result)
    sqli = next(f for f in ctx.findings if f.type == "sql_injection")
    assert sqli.status is FindingStatus.LIKELY  # strong dataflow, but never confirmed
    assert sqli.cwe == "CWE-89"
    html = render_html(ctx)
    assert "CWE-89" in html and "Injection" in html
    assert all(f.status is not FindingStatus.CONFIRMED for f in ctx.findings)


def test_ssrf_status_is_suspicious(tmp_path: Path) -> None:
    (tmp_path / "v.py").write_text(SSRF, encoding="utf-8")
    ctx = scan_to_report_context(scan_repo(str(tmp_path), check_osv=False))
    ssrf = next(f for f in ctx.findings if f.type == "ssrf")
    assert ssrf.status is FindingStatus.SUSPICIOUS
