"""Attack chains: structural linking of findings (ADR-012)."""

from __future__ import annotations

from app.analysis.chains import find_chains
from app.analysis.reporting import scan_to_report_context
from app.analysis.routes import Route
from app.analysis.scanner import scan_repo
from app.core.enums import FindingStatus, Severity
from app.schemas.report import ReportFinding


def finding(type_: str, location: str, severity=Severity.HIGH, title: str | None = None):
    return ReportFinding(
        title=title or type_,
        type=type_,
        severity=severity,
        confidence=0.6,
        status=FindingStatus.SUSPICIOUS,
        endpoint=location,
    )


def route(path: str, line: int, protected: bool, method="GET", file="app.py") -> Route:
    return Route(
        method, path, "python", file, line, f"h{line}", protected, "g" if protected else None
    )


def test_unguarded_route_with_injection_forms_a_chain():
    routes = [route("/a", 10, False), route("/b", 30, False)]
    findings = [finding("sql_injection", "app.py:14", Severity.HIGH)]
    (chain,) = find_chains(findings, routes)
    assert "SQL injection" in chain.title and "GET /a" in chain.title
    assert chain.severity is Severity.HIGH  # never escalated above its worst member
    assert [m.type for m in chain.members][-1] == "sql_injection"
    assert "app.py:14" in chain.fix_first
    assert chain.assumptions  # every chain states what it assumes


def test_finding_in_the_next_handler_is_not_attributed_to_the_previous_route():
    routes = [route("/a", 10, False), route("/b", 30, True)]  # /b is guarded
    findings = [finding("sql_injection", "app.py:35")]
    assert find_chains(findings, routes) == []


def test_guarded_route_makes_no_chain():
    routes = [route("/a", 10, True)]
    assert find_chains([finding("command_injection", "app.py:12")], routes) == []


def test_chain_uses_existing_unguarded_finding_as_entry_member():
    routes = [route("/admin/x", 5, False, "POST")]
    entry = finding("missing_function_level_authorization", "app.py:5", Severity.HIGH)
    inj = finding("code_injection", "app.py:8", Severity.CRITICAL)
    (chain,) = find_chains([entry, inj], routes)
    assert chain.members[0].type == "missing_function_level_authorization"
    assert chain.severity is Severity.CRITICAL


def test_idor_and_privilege_chains():
    routes = [route("/o/<id>", 1, False), route("/p", 20, False, "POST")]
    findings = [
        finding("idor", "app.py:3"),
        finding("client_trusted_privilege", "app.py:22"),
    ]
    titles = {c.title for c in find_chains(findings, routes)}
    assert any("records" in t for t in titles)
    assert any("privilege escalation" in t for t in titles)


def test_cors_and_csrf_chain_needs_both():
    one = [finding("permissive_cors", "app.py:1")]
    both = [*one, finding("csrf_disabled", "app.py:2", Severity.MEDIUM)]
    assert find_chains(one, []) == []
    (chain,) = find_chains(both, [])
    assert "Cross-site" in chain.title and len(chain.members) == 2


def test_chains_are_sorted_by_severity_and_ids_are_stable():
    routes = [route("/a", 1, False), route("/b", 10, False)]
    findings = [
        finding("path_traversal", "app.py:3", Severity.MEDIUM),
        finding("code_injection", "app.py:12", Severity.CRITICAL),
    ]
    chains = find_chains(findings, routes)
    assert [c.severity for c in chains] == [Severity.CRITICAL, Severity.MEDIUM]
    assert [c.id for c in chains] == ["chain-1", "chain-2"]


def test_end_to_end_scan_report_and_json(tmp_path, capsys):
    from app.cli import main

    (tmp_path / "app.py").write_text(
        "import subprocess\n"
        "from flask import Flask, request\n"
        "app = Flask(__name__)\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    return subprocess.check_output('ping ' + request.args['h'], shell=True)\n",
        encoding="utf-8",
    )
    ctx = scan_to_report_context(scan_repo(str(tmp_path), check_osv=False))
    assert any("Command injection" in c.title for c in ctx.attack_chains)

    from app.reports.renderer import render_html

    html = render_html(ctx)
    assert "Attack chains" in html and "reachable without authentication" in html

    main(["scan", str(tmp_path), "--no-osv", "--format", "json"])
    import json

    assert json.loads(capsys.readouterr().out)["attack_chains"]
