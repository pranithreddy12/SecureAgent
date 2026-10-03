import re
from datetime import UTC, datetime

import pytest

from app.models.enums import FindingStatus, Severity
from app.reports.renderer import render_html, render_pdf
from app.schemas.report import NO_CVE, NO_CVSS, CvssScore, ReportContext, ReportFinding

NOW = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)

REQUIRED_SECTIONS = [
    "Executive Summary",
    "Target Information",
    "Audit Information",
    "Authorization Information",
    "Methodology",
    "Attack Surface Summary",
    "Technology Stack Detected",
    "Findings Summary",
    "Severity Distribution",
    "Detailed Findings",
    "Evidence",
    "OWASP Top 10 Mapping",
    "CWE Mapping",
    "CVE Information",
    "CVSS Information",
    "Remediation",
    "Validation Status",
    "Limitations",
    "Audit Timeline",
]


def finding(**kw) -> ReportFinding:
    base = dict(
        title="Missing Content-Security-Policy header",
        type="security_misconfiguration",
        severity=Severity.LOW,
        confidence=0.95,
        status=FindingStatus.CONFIRMED,
        endpoint="https://shop.example.com/",
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-693",
        remediation="Send a restrictive Content-Security-Policy header.",
        sources=["passive-checks"],
    )
    base.update(kw)
    return ReportFinding(**base)


def context(**kw) -> ReportContext:
    base = dict(
        audit_id="0f6c1d2e-0000-4000-8000-000000000001",
        audit_status="completed",
        generated_at=NOW,
        started_at=NOW,
        completed_at=NOW,
        target_name="Example Shop",
        target_url="https://shop.example.com/",
        scope={"allowed_hosts": ["shop.example.com"], "path_prefixes": ["/"]},
        authorized_by="Alice <alice@example.com>",
        authorized_at=NOW,
        authorization_statement="I confirm that I am authorized to perform security testing.",
        methodology=["Reconnaissance", "Scanning", "Safe validation", "Validator", "Report"],
        technologies=["nginx 1.25"],
        endpoints=["/", "/login"],
        findings=[
            finding(),
            finding(
                title="Outdated component",
                type="vulnerable_component",
                severity=Severity.HIGH,
                status=FindingStatus.LIKELY,
                cve="CVE-2021-44228",
                cvss=CvssScore(score=10.0, version="3.1", vector="CVSS:3.1/AV:N/AC:L"),
                owasp_category="A06:2021 Vulnerable and Outdated Components",
                cwe="CWE-1104",
            ),
            finding(
                title="Rejected alert",
                severity=Severity.MEDIUM,
                status=FindingStatus.FALSE_POSITIVE,
                status_reason="Re-check showed the header is present.",
            ),
        ],
    )
    base.update(kw)
    return ReportContext(**base)


def test_all_required_sections_present() -> None:
    html = render_html(context())
    for section in REQUIRED_SECTIONS:
        assert section in html, section


def test_false_positives_excluded_from_counts_but_listed() -> None:
    ctx = context()
    assert [f.title for f in ctx.reportable_findings] == [
        "Outdated component",
        "Missing Content-Security-Policy header",
    ]
    assert ctx.severity_counts[Severity.MEDIUM] == 0  # the rejected alert does not count
    assert ctx.severity_counts[Severity.HIGH] == 1
    html = render_html(ctx)
    assert "Rejected as false positives" in html and "header is present" in html


def test_cve_and_cvss_never_invented() -> None:
    html = render_html(context())
    assert NO_CVE in html and NO_CVSS in html  # finding without identifiers
    assert "CVE-2021-44228" in html and "10.0 (CVSS v3.1)" in html  # supplied values shown
    assert len(re.findall(r"CVE-\d{4}-\d+", html)) == len(re.findall("CVE-2021-44228", html))


def test_untrusted_content_is_escaped() -> None:
    html = render_html(context(findings=[finding(evidence="<b>marker</b> & more")]))
    assert "&lt;b&gt;marker&lt;/b&gt; &amp; more" in html
    assert "<b>marker</b>" not in html


def test_demo_label_only_on_demo_reports() -> None:
    assert "DEMO / SIMULATED SECURITY AUDIT" in render_html(context(is_demo=True))
    assert "DEMO / SIMULATED SECURITY AUDIT" not in render_html(context(is_demo=False))


def test_deterministic_summary_used_without_ai_narrative() -> None:
    html = render_html(context())
    assert "deterministic summary used" in html
    assert "2 reportable finding(s) (1 high, 1 low)" in html
    assert "1 scanner alert(s) were rejected" in html
    custom = render_html(context(executive_summary="Custom narrative."))
    assert "Custom narrative." in custom and "deterministic summary used" not in custom


def test_empty_audit_does_not_claim_absence_of_vulnerabilities() -> None:
    html = render_html(context(findings=[]))
    assert "did not identify reportable security findings" in html
    assert "does not prove the absence of vulnerabilities" in html


def test_pdf_rendering() -> None:
    try:
        pdf = render_pdf(render_html(context(is_demo=True)))
    except (ImportError, OSError) as exc:  # WeasyPrint/Pango absent on this host
        pytest.skip(f"WeasyPrint native libraries unavailable (verified in Docker): {exc}")
    assert pdf.startswith(b"%PDF") and len(pdf) > 5_000
