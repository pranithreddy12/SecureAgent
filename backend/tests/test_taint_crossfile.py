"""Tests for cross-file (project-wide) taint."""

from __future__ import annotations

from pathlib import Path

from app.analysis.scanner import scan_repo
from app.analysis.taint import analyze_taint_project


def vtypes(findings) -> set[str]:
    return {f.vuln_type for f in findings}


HANDLER = """
from flask import request
from db_utils import run_query
@app.route("/u")
def get_user():
    name = request.args.get("name")
    return run_query("SELECT * FROM u WHERE n='" + name + "'")
"""

HELPER = """
import db
def run_query(sql):
    return db.cursor().execute(sql)   # sink in another file
"""

SAFE_HELPER = """
import db
def run_query(name):
    return db.cursor().execute("SELECT * FROM u WHERE n=%s", [name])  # parameterised
"""


def test_cross_file_sql_injection() -> None:
    findings = analyze_taint_project([("views.py", HANDLER), ("db_utils.py", HELPER)])
    sqli = [f for f in findings if f.vuln_type == "sql_injection"]
    assert sqli, "expected a cross-file SQL injection"
    # Reported at the sink's real location, in the other file.
    assert sqli[0].relpath == "db_utils.py"


def test_cross_file_parameterised_is_safe() -> None:
    findings = analyze_taint_project([("views.py", HANDLER), ("db_utils.py", SAFE_HELPER)])
    assert "sql_injection" not in vtypes(findings)


def test_name_collision_resolved_by_import() -> None:
    # Two run_query helpers; the handler imports the one in db_utils.py (vulnerable).
    other = "def run_query(sql):\n    return 'safe constant'\n"
    findings = analyze_taint_project(
        [("views.py", HANDLER), ("db_utils.py", HELPER), ("other.py", other)]
    )
    sqli = [f for f in findings if f.vuln_type == "sql_injection"]
    assert sqli and all(f.relpath == "db_utils.py" for f in sqli)


def test_no_cross_file_without_taint() -> None:
    # Handler passes a constant to the helper -> no finding.
    safe_handler = (
        "from db_utils import run_query\n"
        "@app.route('/x')\ndef h():\n    return run_query('SELECT 1')\n"
    )
    findings = analyze_taint_project([("views.py", safe_handler), ("db_utils.py", HELPER)])
    assert "sql_injection" not in vtypes(findings)


def test_scan_repo_cross_file(tmp_path: Path) -> None:
    (tmp_path / "views.py").write_text(HANDLER, encoding="utf-8")
    (tmp_path / "db_utils.py").write_text(HELPER, encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert any(
        f.vuln_type == "sql_injection" and f.relpath == "db_utils.py" for f in result.taint_findings
    )


def test_single_file_behaviour_preserved(tmp_path: Path) -> None:
    # The within-file interprocedural case still works via the project pass.
    src = (
        "from flask import request\nimport os\n"
        "def run(c):\n    os.system(c)\n"
        "@app.route('/p')\ndef p():\n    run('ping ' + request.args.get('h'))\n"
    )
    (tmp_path / "app.py").write_text(src, encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert any(f.vuln_type == "command_injection" for f in result.taint_findings)
