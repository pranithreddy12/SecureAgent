"""The bundled demo must keep finding what it was built to show -- and stay quiet on the
safe code and placeholders -- so the academic demonstration cannot silently regress."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.cli import main
from app.demo import sample_app_path
from app.reports.renderer import render_html

EXPECTED_TYPES = {
    # injection (taint, including return-value flow and JavaScript)
    "sql_injection",
    "command_injection",
    "code_injection",
    "ssrf",
    "path_traversal",
    "open_redirect",
    # dangerous sinks
    "insecure_deserialization",
    "weak_hash",
    "disabled_tls_verification",
    # access control
    "idor",
    "missing_function_level_authorization",
    # misconfiguration
    "debug_enabled",
    "csrf_disabled",
    "permissive_cors",
    "jwt_verification_disabled",
    # logging and secrets
    "sensitive_data_in_log",
    "swallowed_exception",
    "hardcoded_secret",
}


@pytest.fixture(scope="module")
def demo_findings():
    result = scan_repo(str(sample_app_path()), check_osv=False)
    return scan_to_report_context(result, repo_label="Vulnerable Shop (DEMO)", demo=True)


def test_sample_app_ships_with_the_package() -> None:
    root = sample_app_path()
    for name in ("app.py", "config.py", "safe_routes.py", "server.js", "requirements.txt"):
        assert (root / name).is_file(), name


def test_demo_covers_every_planted_flaw_class(demo_findings) -> None:
    found = {f.type for f in demo_findings.findings}
    assert EXPECTED_TYPES <= found, f"demo no longer shows: {sorted(EXPECTED_TYPES - found)}"


def test_safe_code_produces_no_findings(demo_findings) -> None:
    safe = [f for f in demo_findings.findings if f.endpoint.startswith("safe_routes.py")]
    assert safe == [], f"false positives on correct code: {[f.title for f in safe]}"


def test_placeholder_secret_is_not_reported(demo_findings) -> None:
    config_secrets = [
        f
        for f in demo_findings.findings
        if f.type == "hardcoded_secret" and "config.py" in f.endpoint
    ]
    assert all("SECRET_KEY" not in f.title for f in config_secrets)


def test_provider_key_is_reported_once_not_twice(demo_findings) -> None:
    aws_lines = [
        f
        for f in demo_findings.findings
        if f.type == "hardcoded_secret" and f.endpoint == "config.py:6"
    ]
    assert len(aws_lines) == 1


def test_no_finding_is_ever_confirmed(demo_findings) -> None:
    assert all(f.status.value != "confirmed" for f in demo_findings.findings)


def test_demo_report_is_labelled_and_redacted(demo_findings) -> None:
    html = render_html(demo_findings)
    assert "DEMO / SIMULATED SECURITY AUDIT" in html
    assert "not a real system" in html
    assert "AKIAIOSFODNN7EXAMPLE" not in html  # full secret value never appears
    assert "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5" not in html


def test_demo_command_banner_and_exit_code(capsys: pytest.CaptureFixture) -> None:
    code = main(["demo", "--no-color"])
    out = capsys.readouterr().out
    assert code == 0  # a showcase, not a gate
    assert "DEMO MODE" in out and "NOT a real system" in out
    assert "offline demo" in out  # dependency lookup honestly reported as skipped


def test_demo_command_writes_labelled_report(tmp_path: Path) -> None:
    out = tmp_path / "demo.html"
    assert main(["demo", "--no-color", "--report", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert "DEMO / SIMULATED SECURITY AUDIT" in html and "Vulnerable Shop (DEMO)" in html


def test_ordinary_scans_exclude_demo_fixtures() -> None:
    """Scanning the application source must not pick up the intentionally vulnerable demo."""
    app_dir = Path(__file__).resolve().parent.parent / "app"
    result = scan_repo(str(app_dir), check_osv=False)
    ctx = scan_to_report_context(result)
    assert not any("demo_fixtures" in f.endpoint for f in ctx.findings)
