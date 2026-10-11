"""Source reconnaissance (application model) and rule-based finding validation (ADR-015)."""

from __future__ import annotations

import json
import textwrap

from app.analysis.recon import ApplicationModel
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.validation import RULE_DEV, RULE_TEST, validate_findings
from app.cli import main
from app.core.enums import FindingStatus, Severity
from app.schemas.report import ReportFinding


def finding(type_: str, location: str, status=FindingStatus.SUSPICIOUS, severity=Severity.HIGH):
    return ReportFinding(
        title=type_,
        type=type_,
        severity=severity,
        confidence=0.8,
        status=status,
        endpoint=location,
    )


# ------------------------------------------------------------------ reconnaissance


def test_application_model_from_python_and_js():
    m = ApplicationModel()
    m.absorb_file(
        "app.py",
        textwrap.dedent(
            """
            import os
            import requests
            from flask import Flask, request
            q = request.args.get("q")
            email = request.json["email"]
            token = request.headers.get("X-Token")
            requests.get("https://api.partner.io/v1/items")
            key = os.environ["STRIPE_KEY"]
            url = os.getenv("DATABASE_URL")
            """
        ),
    )
    m.absorb_file(
        "server.js",
        "const express = require('express');\n"
        "const id = req.params.id;\n"
        "const n = req.query.name;\n",
    )
    m.absorb_route_path("/orders/<int:order_id>/items/{item}")
    s = m.summary()
    assert {"Flask", "requests (outbound HTTP)", "Express"} <= set(s["technologies"])
    assert {"query:q", "json:email", "headers:X-Token", "params:id", "query:name"} <= set(
        s["parameters"]
    )
    assert {"path:order_id", "path:item"} <= set(s["parameters"])
    assert s["outbound_hosts"] == ["api.partner.io"]
    assert {"STRIPE_KEY", "DATABASE_URL"} <= set(s["environment_variables"])


def test_localhost_and_non_code_files_are_ignored():
    m = ApplicationModel()
    m.absorb_file("a.py", 'requests.get("http://localhost:8000/x")\n')
    m.absorb_file("README.md", 'see "https://evil.example.org/" and request.args.get("x")')
    assert not m.outbound_hosts and not m.parameters


def test_scan_exposes_the_model_in_report_json_and_cli(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "from flask import Flask, request\n"
        "@app.route('/admin/users/<uid>', methods=['POST'])\n"
        "def f(uid):\n    return request.form['role']\n",
        encoding="utf-8",
    )
    ctx = scan_to_report_context(scan_repo(str(tmp_path), check_osv=False))
    assert "Flask" in ctx.technologies
    assert {"form:role", "path:uid"} <= set(ctx.parameters)
    assert ctx.interesting_paths == ["POST /admin/users/<uid>"]

    main(["scan", str(tmp_path), "--no-osv", "--recon", "--no-color"])
    assert "no live system was contacted" in capsys.readouterr().out
    main(["scan", str(tmp_path), "--no-osv", "--format", "json"])
    assert "form:role" in json.loads(capsys.readouterr().out)["application_model"]["parameters"]


# ------------------------------------------------------------------ validation


def test_findings_in_test_and_example_code_are_reclassified():
    inputs = [
        finding("sql_injection", "tests/test_users.py:10"),
        finding("hardcoded_secret", "frontend/__tests__/api.test.ts:3"),
        finding("hardcoded_secret", "config/settings.py.example:2"),
        finding("sql_injection", "src/users.py:10"),
    ]
    out, applied = validate_findings(inputs)
    assert [f.status for f in out] == [
        FindingStatus.INFORMATIONAL,
        FindingStatus.INFORMATIONAL,
        FindingStatus.INFORMATIONAL,
        FindingStatus.SUSPICIOUS,
    ]
    assert applied[RULE_TEST] == 3
    assert out[0].confidence == 0.4 and out[0].severity is Severity.HIGH  # severity kept
    assert "reclassified" in (out[0].status_reason or "")
    assert out[3] == inputs[3]


def test_dev_only_debug_flag_is_reclassified_but_prod_is_not():
    out, applied = validate_findings(
        [
            finding("debug_enabled", "settings/development.py:4"),
            finding("debug_enabled", "settings/production.py:4"),
            finding("csrf_disabled", "settings/development.py:5"),  # only the debug rule exists
        ]
    )
    assert out[0].status is FindingStatus.INFORMATIONAL
    assert out[1].status is FindingStatus.SUSPICIOUS
    assert out[2].status is FindingStatus.SUSPICIOUS
    assert applied[RULE_DEV] == 1


def test_validation_never_promotes_or_deletes():
    inputs = [finding("sql_injection", "src/a.py:1", FindingStatus.LIKELY)]
    out, _ = validate_findings(inputs)
    assert len(out) == 1 and out[0].status is FindingStatus.LIKELY
    assert all(f.status is not FindingStatus.CONFIRMED for f in out)


def test_reclassified_findings_do_not_drive_risk_or_chains_or_gating(tmp_path, capsys):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(
        "import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8"
    )
    ctx = scan_to_report_context(scan_repo(str(tmp_path), check_osv=False))
    assert ctx.findings and all(f.status is FindingStatus.INFORMATIONAL for f in ctx.findings)
    assert ctx.risk_rating == "None identified"
    assert any("reclassified" in n for n in ctx.validation_notes)
    # a medium finding would fail --fail-on medium; a reclassified one must not
    assert main(["scan", str(tmp_path), "--no-osv", "--fail-on", "medium", "--no-color"]) == 0
    capsys.readouterr()
