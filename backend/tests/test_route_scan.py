"""Tests for static route + authorization extraction and report wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.reporting import scan_to_report_context
from app.analysis.routes import extract_routes, route_findings
from app.analysis.scanner import scan_repo
from app.reports.renderer import render_html

FASTAPI = """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/public")
def public():
    return {}

@router.post("/admin/users")
def create_user(payload: dict):
    return {}

@router.post("/items")
def create_item(user=Depends(get_current_user)):
    return {}

@router.delete("/users/{uid}", dependencies=[Depends(require_admin)])
def delete_user(uid: str):
    return {}
"""

FLASK = """
from flask import Flask
app = Flask(__name__)

@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    return ""

@app.route("/profile")
@login_required
def profile():
    return ""
"""

EXPRESS = """
const express = require('express');
const app = express();
app.post('/admin/reset', resetHandler);
app.get('/account', requireAuth, accountHandler);
app.delete('/users/:id', deleteHandler);
app.get('/about', aboutHandler);
"""


def _find(findings, method, path):
    return next((f for f in findings if f.route.method == method and f.route.path == path), None)


def test_fastapi_routes_and_guards() -> None:
    routes = extract_routes("api.py", FASTAPI)
    by_path = {(r.method, r.path): r for r in routes}
    assert by_path[("GET", "/public")].protected is False
    assert by_path[("POST", "/admin/users")].protected is False
    assert by_path[("POST", "/items")].protected is True  # Depends(get_current_user)
    assert by_path[("DELETE", "/users/{uid}")].protected is True  # dependencies=[Depends(...)]


def test_fastapi_findings_flag_only_unprotected_sensitive() -> None:
    findings = route_findings(extract_routes("api.py", FASTAPI))
    assert _find(findings, "POST", "/admin/users").severity == "high"  # state-changing + privileged
    assert _find(findings, "POST", "/items") is None  # protected
    assert _find(findings, "DELETE", "/users/{uid}") is None  # protected
    assert _find(findings, "GET", "/public") is None  # non-sensitive GET not flagged


def test_flask_decorator_guard() -> None:
    findings = route_findings(extract_routes("views.py", FLASK))
    assert _find(findings, "POST", "/admin/delete") is not None
    assert _find(findings, "GET", "/profile") is None  # @login_required


def test_express_middleware_guard() -> None:
    routes = extract_routes("server.js", EXPRESS)
    findings = route_findings(routes)
    assert _find(findings, "POST", "/admin/reset") is not None
    assert _find(findings, "DELETE", "/users/:id") is not None  # state-changing, no middleware
    assert _find(findings, "GET", "/account") is None  # requireAuth middleware
    assert _find(findings, "GET", "/about") is None  # non-sensitive GET


def test_syntax_error_file_is_skipped_safely() -> None:
    assert extract_routes("broken.py", "def (:\n  pass") == []


def test_scan_repo_collects_routes(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(FASTAPI, encoding="utf-8")
    (tmp_path / "server.js").write_text(EXPRESS, encoding="utf-8")
    result = scan_repo(str(tmp_path))
    assert len(result.routes) >= 8
    assert result.route_findings  # at least the unprotected sensitive ones


def test_scan_to_report_renders_html(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(FASTAPI, encoding="utf-8")
    (tmp_path / "config.py").write_text(
        'API_SECRET = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"\n', encoding="utf-8"
    )
    result = scan_repo(str(tmp_path))
    ctx = scan_to_report_context(result)
    html = render_html(ctx)
    assert "Broken Access Control" in html
    assert "Hardcoded secret" in html
    assert "no live target" in html  # honest: static-only
    assert "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5" not in html  # secret stays redacted


def test_report_findings_have_honest_status(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(FASTAPI, encoding="utf-8")
    result = scan_repo(str(tmp_path))
    ctx = scan_to_report_context(result)
    # Static route findings are never "confirmed".
    statuses = {f.status.value for f in ctx.findings}
    assert "confirmed" not in statuses


@pytest.mark.parametrize("path", ["/health", "/about", "/docs"])
def test_benign_get_paths_not_flagged(path: str) -> None:
    src = f'@app.get("{path}")\ndef h():\n    return {{}}\n'
    assert route_findings(extract_routes("a.py", src)) == []
