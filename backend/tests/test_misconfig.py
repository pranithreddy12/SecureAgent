"""Tests for security-misconfiguration detection (batch #4)."""

from __future__ import annotations

from pathlib import Path

from app.analysis.misconfig import scan_misconfig
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.models.enums import FindingStatus
from app.reports.renderer import render_html


def cats(src: str) -> set[str]:
    return {f.category for f in scan_misconfig("app.py", src)}


def test_debug_enabled_variants() -> None:
    assert "debug_enabled" in cats("DEBUG = True\n")
    assert "debug_enabled" in cats("app.debug = True\n")
    assert "debug_enabled" in cats("app.run(debug=True)\n")


def test_debug_false_not_flagged() -> None:
    assert "debug_enabled" not in cats("DEBUG = False\n")


def test_permissive_cors_with_credentials_is_high() -> None:
    src = "app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True)\n"
    findings = scan_misconfig("app.py", src)
    cors = next(f for f in findings if f.category == "permissive_cors")
    assert cors.severity == "high"


def test_cors_specific_origin_not_flagged() -> None:
    src = "CORS(app, origins=['https://example.com'], supports_credentials=True)\n"
    assert "permissive_cors" not in cats(src)


def test_jwt_verification_disabled() -> None:
    assert "jwt_verification_disabled" in cats("jwt.decode(tok, verify=False)\n")
    assert "jwt_verification_disabled" in cats(
        "jwt.decode(tok, key, options={'verify_signature': False})\n"
    )
    assert "jwt_verification_disabled" in cats("jwt.decode(tok, algorithms=['none'])\n")


def test_jwt_safe_not_flagged() -> None:
    assert "jwt_verification_disabled" not in cats("jwt.decode(tok, key, algorithms=['HS256'])\n")


def test_csrf_disabled() -> None:
    assert "csrf_disabled" in cats("WTF_CSRF_ENABLED = False\n")
    assert "csrf_disabled" in cats("@csrf_exempt\ndef view():\n    pass\n")


def test_autoescape_off() -> None:
    assert "template_autoescape_off" in cats("env = Environment(autoescape=False)\n")
    assert "template_autoescape_off" not in cats("env = Environment(autoescape=True)\n")


def test_allowed_hosts_wildcard() -> None:
    assert "allowed_hosts_wildcard" in cats("ALLOWED_HOSTS = ['*']\n")
    assert "allowed_hosts_wildcard" not in cats("ALLOWED_HOSTS = ['example.com']\n")


def test_insecure_cookie() -> None:
    assert "insecure_cookie" in cats("resp.set_cookie('s', v, secure=False)\n")
    assert "insecure_cookie" not in cats("resp.set_cookie('s', v, secure=True, httponly=True)\n")


def test_config_subscript_debug() -> None:
    assert "debug_enabled" in cats("app.config['DEBUG'] = True\n")


def test_syntax_error_safe() -> None:
    assert scan_misconfig("app.py", "def (:\n") == []


def test_misconfig_in_scan_and_report(tmp_path: Path) -> None:
    (tmp_path / "settings.py").write_text("DEBUG = True\nALLOWED_HOSTS = ['*']\n", encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert len(result.misconfig_findings) == 2
    ctx = scan_to_report_context(result)
    debug = next(f for f in ctx.findings if f.type == "debug_enabled")
    assert debug.status is FindingStatus.LIKELY
    assert debug.cwe == "CWE-489"
    html = render_html(ctx)
    assert "CWE-489" in html and "Security Misconfiguration" in html
