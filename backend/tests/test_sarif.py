"""Tests for SARIF 2.1.0 output."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.sarif import to_sarif
from app.cli import main
from app.models.enums import FindingStatus, Severity
from app.schemas.report import ReportFinding


def rf(**kw) -> ReportFinding:
    base = dict(
        title="SQL Injection (tainted input → execute)",
        type="sql_injection",
        severity=Severity.HIGH,
        confidence=0.75,
        status=FindingStatus.LIKELY,
        endpoint="app/views.py:42",
        cwe="CWE-89",
        owasp_category="A03:2021 Injection",
        remediation="Use parameterised queries.",
    )
    base.update(kw)
    return ReportFinding(**base)


def test_sarif_skeleton() -> None:
    doc = to_sarif([rf()])
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "SecureAgent"
    assert any(r["id"] == "sql_injection" for r in driver["rules"])


def test_result_fields_and_location() -> None:
    res = to_sarif([rf()])["runs"][0]["results"][0]
    assert res["ruleId"] == "sql_injection"
    assert res["level"] == "error"  # high -> error
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/views.py"
    assert loc["region"]["startLine"] == 42
    assert res["properties"]["security-severity"] == "8.0"
    assert res["properties"]["cwe"] == "CWE-89"
    assert "secureagent/v1" in res["partialFingerprints"]


def test_level_mapping() -> None:
    levels = {
        f.severity.value: to_sarif([f])["runs"][0]["results"][0]["level"]
        for f in [rf(severity=s) for s in Severity]
    }
    assert levels["critical"] == "error"
    assert levels["high"] == "error"
    assert levels["medium"] == "warning"
    assert levels["low"] == "note"
    assert levels["informational"] == "note"


def test_windows_path_normalised_and_depfinding_line_default() -> None:
    res = to_sarif([rf(endpoint="app\\pkg\\views.py:7")])["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/pkg/views.py"
    dep = to_sarif([rf(type="vulnerable_dependency", endpoint="requirements.txt")])
    region = dep["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1  # no line in endpoint -> default


def test_help_uri_from_cwe() -> None:
    rule = to_sarif([rf()])["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/89.html"


def test_one_rule_per_type() -> None:
    doc = to_sarif([rf(), rf(endpoint="a.py:1"), rf(type="ssrf", cwe="CWE-918")])
    ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert sorted(ids) == ["sql_injection", "ssrf"]


def test_cli_sarif_output(tmp_path: Path, capsys) -> None:
    (tmp_path / "v.py").write_text(
        "from flask import request\n@app.route('/x')\ndef h():\n"
        "    import os; os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    main(["scan", str(tmp_path), "--no-osv", "--format", "sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], "expected at least one SARIF result"
