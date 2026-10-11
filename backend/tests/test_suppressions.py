"""Justified, expiring finding suppressions (the feedback loop)."""

from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path

import pytest

from app.analysis.baseline import fingerprint
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.suppressions import FILENAME, Suppression, SuppressionError, add, load
from app.cli import main
from app.core.enums import FindingStatus

APP = "import hashlib\nhashlib.md5(b'a')\n"


def project(tmp_path: Path, text: str = APP) -> Path:
    (tmp_path / "app.py").write_text(text, encoding="utf-8")
    return tmp_path


def findings(root: Path):
    return scan_to_report_context(scan_repo(str(root), check_osv=False)).findings


def entry(**kw) -> Suppression:
    base = {
        "fingerprint": "",
        "type": "weak_hash",
        "location": "app.py",
        "title": "t",
        "reason": "MD5 is only a cache key here, never a password hash",
        "by": "dev",
        "created": date.today().isoformat(),
    }
    return Suppression(**{**base, **kw})


def fp_of(root: Path) -> str:
    return fingerprint(findings(root)[0])


def test_cli_list_then_suppress_then_finding_is_a_justified_false_positive(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["suppress", str(root), "--list"]) == 0
    listing = capsys.readouterr().out
    fid = listing.split()[0]
    assert len(fid) == 8 and "weak hash" in listing.lower()

    code = main(
        ["suppress", str(root), "--id", fid, "--reason", "cache key only, never a password hash",
         "--by", "dev", "--expires", (date.today() + timedelta(days=30)).isoformat()]
    )  # fmt: skip
    assert code == 0
    saved = json.loads((root / FILENAME).read_text(encoding="utf-8"))["suppressions"]
    assert saved[0]["by"] == "dev" and saved[0]["count"] == 1 and saved[0]["location"] == "app.py"

    after = findings(root)
    assert [f.status for f in after] == [FindingStatus.FALSE_POSITIVE]
    assert "Suppressed by dev" in after[0].status_reason
    assert "cache key only" in after[0].status_reason


def test_suppressed_findings_do_not_fail_a_gate_or_show_in_the_text_list(tmp_path, capsys):
    root = project(tmp_path)
    assert main(["scan", str(root), "--no-osv", "--fail-on", "low", "--no-color"]) == 1
    capsys.readouterr()
    add(str(root / FILENAME), entry(fingerprint=fp_of(root)))
    assert main(["scan", str(root), "--no-osv", "--fail-on", "low", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "weak hash" not in out and "suppressed" in out


def test_a_reason_is_required(tmp_path, capsys):
    root = project(tmp_path)
    fid = fp_of(root)[:8]
    assert main(["suppress", str(root), "--id", fid, "--reason", "nope"]) == 2
    assert not (root / FILENAME).exists()
    bad = {"suppressions": [{"fingerprint": fid, "reason": "short"}]}
    (root / FILENAME).write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(SuppressionError):
        load(str(root / FILENAME))


def test_expired_suppression_stops_applying_and_is_reported(tmp_path):
    root = project(tmp_path)
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    add(str(root / FILENAME), entry(fingerprint=fp_of(root), expires=yesterday))
    ctx = scan_to_report_context(scan_repo(str(root), check_osv=False))
    assert ctx.findings[0].status is not FindingStatus.FALSE_POSITIVE
    assert any("expired" in n for n in ctx.validation_notes)


def test_a_new_identical_finding_is_not_silently_hidden(tmp_path):
    root = project(tmp_path)
    add(str(root / FILENAME), entry(fingerprint=fp_of(root), count=1))
    # a second MD5 use appears later in the same file
    (root / "app.py").write_text(APP + "hashlib.md5(b'b')\n", encoding="utf-8")
    statuses = sorted(f.status.value for f in findings(root))
    assert statuses == ["false_positive", "likely"] or statuses == ["false_positive", "suspicious"]


def test_ambiguous_or_unknown_id_is_rejected(tmp_path, capsys):
    root = project(tmp_path)
    assert (
        main(["suppress", str(root), "--id", "ffffffff", "--reason", "does not exist anywhere"])
        == 2
    )
    assert "no finding" in capsys.readouterr().err


def test_suppressed_findings_do_not_form_attack_chains(tmp_path):
    src = (
        "import subprocess\nfrom flask import Flask, request\napp = Flask(__name__)\n"
        "@app.route('/ping')\ndef ping():\n"
        "    return subprocess.check_output('ping ' + request.args['h'], shell=True)\n"
    )
    root = project(tmp_path, src)
    ctx = scan_to_report_context(scan_repo(str(root), check_osv=False))
    assert ctx.attack_chains
    for f in ctx.findings:
        if f.type == "command_injection":
            add(str(root / FILENAME), entry(fingerprint=fingerprint(f), type=f.type, title=f.title))
    after = scan_to_report_context(scan_repo(str(root), check_osv=False))
    assert after.attack_chains == []
