"""Tests for baseline fingerprints and CI gating."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.baseline import fails_threshold, fingerprint, load_baseline, write_baseline
from app.cli import main
from app.models.enums import FindingStatus, Severity
from app.schemas.report import ReportFinding


def rf(**kw) -> ReportFinding:
    base = dict(
        title="SQL Injection",
        type="sql_injection",
        severity=Severity.HIGH,
        confidence=0.75,
        status=FindingStatus.LIKELY,
        endpoint="app/views.py:42",
    )
    base.update(kw)
    return ReportFinding(**base)


def test_fingerprint_stable_across_line_moves() -> None:
    a = fingerprint(rf(endpoint="app/views.py:42"))
    b = fingerprint(rf(endpoint="app/views.py:88"))  # same finding, moved
    assert a == b


def test_fingerprint_differs_by_type_and_location() -> None:
    assert fingerprint(rf()) != fingerprint(rf(type="ssrf"))
    assert fingerprint(rf()) != fingerprint(rf(endpoint="app/other.py:42"))


def test_write_and_load_baseline_roundtrip(tmp_path: Path) -> None:
    path = str(tmp_path / "bl.json")
    n = write_baseline(path, ["aaa", "bbb", "aaa"])
    assert n == 2
    assert load_baseline(path) == {"aaa", "bbb"}


def test_load_missing_baseline_is_empty(tmp_path: Path) -> None:
    assert load_baseline(str(tmp_path / "nope.json")) == set()


def test_fails_threshold() -> None:
    assert fails_threshold("critical", "high")
    assert fails_threshold("high", "high")
    assert not fails_threshold("medium", "high")
    assert fails_threshold("low", None)  # no threshold -> any finding fails


# --- end-to-end CLI gating ---

VULN = "@app.route('/x')\ndef h():\n    import os\n    os.system(request.args.get('c'))\n"


def _repo(tmp_path: Path) -> str:
    (tmp_path / "v.py").write_text("from flask import request\n" + VULN, encoding="utf-8")
    return str(tmp_path)


def test_cli_fails_without_baseline(tmp_path: Path) -> None:
    assert main(["scan", _repo(tmp_path), "--no-osv", "--no-color"]) == 1


def test_cli_baseline_suppresses_known(tmp_path: Path, capsys) -> None:
    repo = _repo(tmp_path)
    bl = str(tmp_path / "bl.json")
    assert main(["scan", repo, "--no-osv", "--write-baseline", bl]) == 0
    capsys.readouterr()
    # With everything baselined, no new findings -> exit 0.
    assert main(["scan", repo, "--no-osv", "--no-color", "--baseline", bl]) == 0
    assert "suppressed" in capsys.readouterr().out


def test_cli_baseline_flags_new_finding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    bl = str(tmp_path / "bl.json")
    main(["scan", repo, "--no-osv", "--write-baseline", bl])
    # Introduce a new, different vulnerability.
    (Path(repo) / "v2.py").write_text(
        "from flask import request\n@app.route('/y')\ndef h2():\n    eval(request.args.get('e'))\n",
        encoding="utf-8",
    )
    assert main(["scan", repo, "--no-osv", "--no-color", "--baseline", bl]) == 1


def test_cli_fail_on_threshold(tmp_path: Path) -> None:
    # A medium-only finding should pass a --fail-on high gate.
    (tmp_path / "s.py").write_text("DEBUG = True\n", encoding="utf-8")  # medium misconfig
    assert main(["scan", str(tmp_path), "--no-osv", "--no-color", "--fail-on", "high"]) == 0
    assert main(["scan", str(tmp_path), "--no-osv", "--no-color", "--fail-on", "medium"]) == 1


def test_cli_json_has_fingerprints_and_summary(tmp_path: Path, capsys) -> None:
    main(["scan", _repo(tmp_path), "--no-osv", "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["total"] >= 1
    assert all("fingerprint" in f for f in data["findings"])
