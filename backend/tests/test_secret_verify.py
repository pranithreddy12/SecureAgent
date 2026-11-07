"""Opt-in secret liveness check (--verify-secrets). Providers are faked; nothing leaves the box."""

from __future__ import annotations

from pathlib import Path

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.secret_verify import verify_secrets
from app.core.enums import FindingStatus

GH_LIVE = "ghp_" + "A" * 36
GH_DEAD = "ghp_" + "B" * 36
STRIPE = "sk_live_" + "C" * 24


def _fake(calls: list):
    def fetch(url, method, headers, body):
        calls.append(url)
        if "github" in url:
            return (200, b"{}") if GH_LIVE in headers["Authorization"] else (401, b"")
        if "stripe" in url:
            return 401, b""
        return 500, b""

    return fetch


def test_liveness_drives_status_and_values_go_only_to_their_provider(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        f'GH = "{GH_LIVE}"\nOLD = "{GH_DEAD}"\nPAY = "{STRIPE}"\nAGAIN = "{GH_LIVE}"\n',
        encoding="utf-8",
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    calls: list[str] = []
    result.secret_findings = verify_secrets(str(tmp_path), result.secret_findings, _fake(calls))
    by_line = {f.line: f.liveness for f in result.secret_findings}
    assert by_line[1] == "live" and by_line[2] == "revoked" and by_line[3] == "revoked"
    assert calls.count("https://api.github.com/user") == 2  # same key on line 4: cached
    assert all(u.startswith("https://api.") for u in calls)

    statuses = {
        f.endpoint: f.status for f in scan_to_report_context(result).findings
        if f.type == "hardcoded_secret"
    }  # fmt: skip
    assert statuses["config.py:1"] is FindingStatus.CONFIRMED
    assert statuses["config.py:2"] is FindingStatus.INFORMATIONAL


def test_unverifiable_kinds_are_left_alone(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('KEY = "AKIA' + "Z" * 16 + '"\n', encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    out = verify_secrets(str(tmp_path), result.secret_findings, _fake([]))
    assert [f.liveness for f in out] == [None]
