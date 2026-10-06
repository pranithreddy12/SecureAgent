"""Tests for IDOR / object-level authorization analysis (batch #3)."""

from __future__ import annotations

from pathlib import Path

from app.analysis.access_control import analyze_access_control
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.models.enums import FindingStatus
from app.reports.renderer import render_html


def flagged(src: str) -> bool:
    return bool(analyze_access_control("v.py", src))


VULN_FASTAPI = """
@router.get("/orders/{order_id}")
def get_order(order_id: int, db=Depends(get_db)):
    return db.query(Order).get(order_id)
"""

VULN_FLASK = """
@app.route("/doc/<doc_id>")
def view_doc(doc_id):
    return Document.query.get_or_404(doc_id)
"""

SAFE_SCOPED = """
@router.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_current_user), db=Depends(get_db)):
    return db.query(Order).filter_by(id=order_id, user_id=current_user.id).first()
"""

SAFE_OWNERSHIP_CHECK = """
@router.get("/orders/{order_id}")
def get_order(order_id: int, current_user=Depends(get_current_user), db=Depends(get_db)):
    order = db.query(Order).get(order_id)
    if order.user_id != current_user.id:
        raise HTTPException(403)
    return order
"""

ADMIN_ONLY = """
@router.get("/orders/{order_id}")
@require_admin
def get_order(order_id: int, db=Depends(get_db)):
    return db.query(Order).get(order_id)
"""

NOT_A_DB_GET = """
@app.route("/x")
def h():
    return config.get(request.args.get("k"))
"""


def test_vulnerable_fastapi_flagged() -> None:
    assert flagged(VULN_FASTAPI)


def test_vulnerable_flask_get_or_404_flagged() -> None:
    assert flagged(VULN_FLASK)


def test_scoped_query_is_safe() -> None:
    assert not flagged(SAFE_SCOPED)


def test_ownership_comparison_is_safe() -> None:
    assert not flagged(SAFE_OWNERSHIP_CHECK)


def test_admin_only_is_not_flagged() -> None:
    assert not flagged(ADMIN_ONLY)


def test_dict_get_not_flagged() -> None:
    assert not flagged(NOT_A_DB_GET)


def test_non_handler_not_flagged() -> None:
    src = "def helper(order_id, db):\n    return db.query(Order).get(order_id)\n"
    assert not flagged(src)


def test_constant_id_not_flagged() -> None:
    src = "@app.route('/x')\ndef h():\n    return db.query(Order).get(1)\n"
    assert not flagged(src)


def test_confidence_lower_when_user_referenced() -> None:
    # References current_user but does not actually scope the query -> flagged, low conf.
    src = (
        "@router.get('/o/{oid}')\n"
        "def h(oid: int, current_user=Depends(get_current_user), db=Depends(get_db)):\n"
        "    log(current_user.id)\n"
        "    return db.query(Order).get(oid)\n"
    )
    findings = analyze_access_control("v.py", src)
    assert findings and findings[0].confidence == 0.4


def test_idor_in_scan_and_report(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(VULN_FASTAPI, encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert result.idor_findings
    ctx = scan_to_report_context(result)
    idor = next(f for f in ctx.findings if f.type == "idor")
    assert idor.status is FindingStatus.SUSPICIOUS
    assert idor.cwe == "CWE-639"
    html = render_html(ctx)
    assert "CWE-639" in html and "Broken Access Control" in html
