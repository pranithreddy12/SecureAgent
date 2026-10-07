"""Tests for A09 logging & monitoring checks."""

from __future__ import annotations

from pathlib import Path

from app.analysis.logging_checks import scan_logging
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.models.enums import FindingStatus
from app.reports.renderer import render_html


def cats(src: str) -> set[str]:
    return {f.category for f in scan_logging("m.py", src)}


def test_sensitive_data_in_log_variants() -> None:
    assert "sensitive_data_in_log" in cats("import logging\nlogging.info('pw=' + password)\n")
    assert "sensitive_data_in_log" in cats("logger.debug(f'token={access_token}')\n")
    assert "sensitive_data_in_log" in cats("print(user_password)\n")
    assert "sensitive_data_in_log" in cats("log.error('secret is %s', client_secret)\n")


def test_non_sensitive_log_not_flagged() -> None:
    assert "sensitive_data_in_log" not in cats("logger.info('user logged in: ' + username)\n")
    assert "sensitive_data_in_log" not in cats("logging.info('processing order %s', order_id)\n")


def test_non_logger_method_not_flagged() -> None:
    # .info / .error on something that is not a logger should not trip the check.
    assert "sensitive_data_in_log" not in cats("response.error(password)\n")


def test_swallowed_exception() -> None:
    assert "swallowed_exception" in cats("try:\n    risky()\nexcept Exception:\n    pass\n")
    assert "swallowed_exception" in cats("try:\n    risky()\nexcept:\n    ...\n")


def test_handled_exception_not_flagged() -> None:
    assert "swallowed_exception" not in cats(
        "try:\n    risky()\nexcept Exception as e:\n    logger.error(e)\n"
    )
    assert "swallowed_exception" not in cats("try:\n    risky()\nexcept Exception:\n    raise\n")


def test_syntax_error_safe() -> None:
    assert scan_logging("m.py", "def (:\n") == []


def test_non_python_file_ignored() -> None:
    assert scan_logging("a.js", "console.log(password)\n") == []


def test_logging_in_scan_and_report(tmp_path: Path) -> None:
    (tmp_path / "svc.py").write_text(
        "import logging\n"
        "def login(password):\n"
        "    logging.info('attempt pw=' + password)\n"
        "    try:\n        auth()\n    except Exception:\n        pass\n",
        encoding="utf-8",
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    assert len(result.logging_findings) == 2
    ctx = scan_to_report_context(result)
    sens = next(f for f in ctx.findings if f.type == "sensitive_data_in_log")
    assert sens.status is FindingStatus.LIKELY
    assert sens.cwe == "CWE-532"
    html = render_html(ctx)
    assert "CWE-532" in html and "Logging and Monitoring" in html
