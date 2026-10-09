"""Tests for the report polish: risk rating, consolidated groups, priorities, compact sections."""

from __future__ import annotations

import re

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.demo import sample_app_path
from app.models.enums import FindingStatus, Severity
from app.reports.renderer import render_html
from app.schemas.report import NO_CVE, NO_CVSS, CvssScore
from tests.test_reports import context, finding


def ctx_of(*findings, **kw):
    return context(findings=list(findings), **kw)


def section(html: str, start_id: str, end_id: str) -> str:
    a = html.index(f'id="{start_id}"')
    b = html.index(f'id="{end_id}"')
    return html[a:b]


# --------------------------------------------------------------- risk rating


def test_risk_rating_is_highest_reportable_severity() -> None:
    assert ctx_of(finding(severity=Severity.CRITICAL)).risk_rating == "Critical"
    assert ctx_of(finding(severity=Severity.MEDIUM)).risk_rating == "Moderate"
    assert ctx_of(finding(severity=Severity.LOW)).risk_rating == "Low"
    assert ctx_of().risk_rating == "None identified"


def test_false_positives_never_raise_the_rating() -> None:
    fp = finding(severity=Severity.CRITICAL, status=FindingStatus.FALSE_POSITIVE)
    assert ctx_of(fp, finding(severity=Severity.LOW)).risk_rating == "Low"


def test_risk_basis_flags_unverified_findings() -> None:
    basis = ctx_of(finding(status=FindingStatus.SUSPICIOUS)).risk_basis
    assert "1 suspicious" in basis and "unverified" in basis


def test_risk_basis_has_no_caveat_when_everything_confirmed() -> None:
    basis = ctx_of(finding(status=FindingStatus.CONFIRMED)).risk_basis
    assert "1 confirmed" in basis and "unverified" not in basis


# --------------------------------------------------------------- grouping and priority


def test_same_type_findings_consolidate_into_one_group() -> None:
    c = ctx_of(
        finding(type="sql_injection", severity=Severity.MEDIUM, endpoint="a.py:3"),
        finding(type="sql_injection", severity=Severity.HIGH, endpoint="b.py:9"),
        finding(type="sql_injection", severity=Severity.HIGH, endpoint="a.py:3"),  # same place
    )
    groups = c.finding_groups
    assert len(groups) == 1
    g = groups[0]
    assert g.count == 3
    assert g.worst_severity is Severity.HIGH
    assert g.locations == ["a.py:3", "b.py:9"]  # de-duplicated and sorted


def test_groups_ordered_by_severity_then_trust_then_size() -> None:
    c = ctx_of(
        finding(type="weak_hash", severity=Severity.MEDIUM, status=FindingStatus.LIKELY),
        finding(type="idor", severity=Severity.MEDIUM, status=FindingStatus.SUSPICIOUS),
        finding(type="idor", severity=Severity.MEDIUM, status=FindingStatus.SUSPICIOUS),
        finding(type="rce", severity=Severity.CRITICAL, status=FindingStatus.SUSPICIOUS),
    )
    # critical first; then equal severity: 'likely' outranks 'suspicious' despite fewer items.
    assert [g.type for g in c.finding_groups] == ["rce", "weak_hash", "idor"]


def test_confirmed_outranks_suspicious_at_equal_severity() -> None:
    sus = finding(title="sus", severity=Severity.HIGH, status=FindingStatus.SUSPICIOUS)
    con = finding(title="con", severity=Severity.HIGH, status=FindingStatus.CONFIRMED)
    assert [f.title for f in ctx_of(sus, con).reportable_findings] == ["con", "sus"]


def test_hotspots_group_by_file_and_ignore_line_numbers() -> None:
    c = ctx_of(
        finding(endpoint="app.py:10"),
        finding(endpoint="app.py:99"),
        finding(endpoint="config.py:1"),
        finding(endpoint="b.py:5"),
    )
    assert c.hotspots(2) == [("app.py", 2), ("b.py", 1)]  # ties broken alphabetically


# --------------------------------------------------------------- rendered report


def test_type_labels_keep_acronyms() -> None:
    from app.schemas.report import type_label

    assert type_label("sql_injection") == "SQL injection"
    assert type_label("disabled_tls_verification") == "Disabled TLS verification"
    assert type_label("idor") == "IDOR"
    assert type_label("code_injection") == "Code injection"


def test_toc_links_resolve_to_real_anchors() -> None:
    html = render_html(ctx_of(finding()))
    for n in (1, 8, 16, 19):
        assert f'href="#s{n}"' in html and f'id="s{n}"' in html


def test_glance_block_shows_rating_and_fix_first() -> None:
    c = ctx_of(
        finding(type="sql_injection", severity=Severity.HIGH, remediation="Use bound parameters."),
        finding(type="sql_injection", severity=Severity.HIGH, endpoint="b.py:2"),
    )
    html = render_html(c)
    assert 'class="risk risk-high"' in html
    assert "Fix first" in html and "SQL injection" in html and "2 locations" in html
    assert "Use bound parameters." in html


def test_grouped_remediation_table_lists_each_fix_once() -> None:
    fix = "Use bound parameters, never string concatenation."
    c = ctx_of(
        finding(type="sql_injection", endpoint="a.py:1", remediation=fix),
        finding(type="sql_injection", endpoint="b.py:2", remediation=fix),
        finding(type="sql_injection", endpoint="c.py:3", remediation=fix),
    )
    s16 = section(render_html(c), "s16", "s17")
    assert s16.count(fix) == 1  # not repeated per finding
    assert "3 locations" in s16 and "a.py:1" in s16 and "c.py:3" in s16


def test_cve_and_cvss_sections_are_compact_but_still_honest() -> None:
    c = ctx_of(
        finding(endpoint="a.py:1"),
        finding(endpoint="b.py:2"),
        finding(
            title="Old lib",
            type="vulnerable_dependency",
            cve="CVE-2021-44228",
            cvss=CvssScore(score=10.0, version="3.1"),
        ),
    )
    html = render_html(c)
    s14, s15 = section(html, "s14", "s15"), section(html, "s15", "s16")
    assert s14.count(NO_CVE) == 1 and "2 of 3 finding(s)" in s14  # one counted note
    assert "CVE-2021-44228" in s14
    assert s15.count(NO_CVSS) == 1 and "2 of 3 finding(s)" in s15
    assert "10.0 (CVSS v3.1)" in s15


def test_all_sections_still_present_after_polish() -> None:
    html = render_html(ctx_of(finding()))
    ids = set(re.findall(r'<h2 id="s(\d+)"', html))
    assert ids == {str(n) for n in range(1, 20)} - {"11"}  # 10 and 11 share one heading


def test_new_blocks_escape_untrusted_text() -> None:
    evil = '<img src=x onerror="alert(1)">'
    html = render_html(ctx_of(finding(remediation=evil, endpoint="<b>x</b>.py:1")))
    assert evil not in html and "<b>x</b>.py" not in html
    assert "&lt;img" in html


def test_demo_report_leads_with_the_critical_issue() -> None:
    result = scan_repo(str(sample_app_path()), check_osv=False)
    c = scan_to_report_context(result, demo=True)
    assert c.risk_rating == "Critical"
    assert c.finding_groups[0].type == "code_injection"
    html = render_html(c)
    assert html.index("Fix first") < html.index('id="s2"')  # surfaced up front
    # Consolidation: the demo has far more findings than distinct issue types.
    assert len(c.finding_groups) < len(c.reportable_findings)
