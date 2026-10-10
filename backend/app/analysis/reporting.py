"""Turn a static ScanResult into the shared ReportContext (Phase 13) for HTML/PDF."""

from __future__ import annotations

import getpass
import os
import uuid
from datetime import UTC, datetime

from app.analysis.scanner import ScanResult
from app.core.enums import FindingStatus, Severity
from app.schemas.report import ReportContext, ReportFinding

AUTHORIZATION_STATEMENT = (
    "I confirm that I am authorized to analyse the source code scanned in this report."
)


def _secret_finding(f) -> ReportFinding:
    return ReportFinding(
        title=f.title,
        type="hardcoded_secret",
        severity=Severity(f.severity),
        confidence=f.confidence,
        # It is in the source, but whether it is live/active is not proven here.
        status=FindingStatus.LIKELY,
        status_reason="Matched a secret pattern in source; value redacted.",
        endpoint=f"{f.relpath}:{f.line}",
        evidence=f"{f.rule} — {f.redacted} (fingerprint {f.fingerprint})",
        validation_method="static source pattern match",
        owasp_category="A05:2021 Security Misconfiguration",
        cwe="CWE-798",
        remediation=(
            "Remove the secret from source, rotate it immediately, and load it from an "
            "environment variable or a secrets manager instead."
        ),
        sources=["static:secrets"],
    )


def _dependency_finding(f) -> ReportFinding:
    d = f.dependency
    ids = ", ".join(v.id for v in f.vulns[:10])
    cve = next((v.cve for v in f.vulns if v.cve), None)
    severity = f.severity if f.severity != "unknown" else "medium"
    return ReportFinding(
        title=f.title,
        type="vulnerable_dependency",
        severity=Severity(severity),
        confidence=f.confidence,
        status=FindingStatus.LIKELY,
        status_reason=f"The lockfile declares {d.name} {d.version}, which has known advisories.",
        endpoint=d.relpath,
        parameter=f"{d.ecosystem}:{d.name}@{d.version}",
        description=f"{len(f.vulns)} known advisory/advisories affect this version: {ids}.",
        impact="Known-vulnerable dependencies can be exploited through your application.",
        evidence="; ".join(f"{v.id} [{v.severity}] {v.summary}".strip() for v in f.vulns[:10]),
        validation_method="dependency manifest matched against the OSV database",
        owasp_category="A06:2021 Vulnerable and Outdated Components",
        cwe="CWE-1104",
        cve=cve,  # only a real advisory id; never invented
        remediation="Upgrade to a non-vulnerable version listed in the advisories.",
        sources=["static:dependencies(osv)"],
    )


def _logging_finding(f) -> ReportFinding:
    return ReportFinding(
        title=f.title,
        type=f.category,
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=FindingStatus.LIKELY,
        status_reason="Logging/monitoring weakness present in source.",
        endpoint=f"{f.relpath}:{f.line}",
        evidence=f"{f.rule} — {f.evidence}",
        validation_method="static logging analysis",
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:logging"],
    )


def _logic_finding(f) -> ReportFinding:
    intent = f.category == "intent_violation"
    return ReportFinding(
        title=f.title,
        type=f.category,
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=FindingStatus.SUSPICIOUS,
        status_reason=(
            "The source does not show a rule the developer declared (secureagent-intent.json)."
            if intent
            else "The handler uses a client-controlled value where the server should decide. "
            "Confirm no serializer/middleware outside the handler neutralises it."
        ),
        endpoint=f"{f.relpath}:{f.line}",
        parameter=f.field,
        description=f"Handler {f.handler}(): {f.rule}.",
        impact="A client can tamper with values or privileges the server is meant to control.",
        evidence=f.evidence,
        validation_method="static business-logic analysis"
        + (" (developer intent spec)" if intent else ""),
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:business-logic"],
    )


def _misconfig_finding(f) -> ReportFinding:
    return ReportFinding(
        title=f.title,
        type=f.category,
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=FindingStatus.LIKELY,  # the setting is present in the source
        status_reason="Insecure configuration present in source.",
        endpoint=f"{f.relpath}:{f.line}",
        evidence=f"{f.rule} — {f.evidence}",
        validation_method="static configuration analysis",
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:misconfig"],
    )


def _idor_finding(f) -> ReportFinding:
    return ReportFinding(
        title=f.title,
        type="idor",
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=FindingStatus.SUSPICIOUS,
        status_reason=(
            "A record is fetched by a request-supplied id with no ownership scoping "
            "detected. Confirm the caller is authorized for this object (ownership may be "
            "enforced elsewhere)."
        ),
        endpoint=f"{f.relpath}:{f.line}",
        parameter=f.lookup,
        description=f"Handler {f.handler}() looks up a record via {f.lookup} using input.",
        impact="Another user could read or modify an object they do not own.",
        evidence=f"lookup: {f.lookup}",
        validation_method="static access-control analysis",
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:access-control"],
    )


def _taint_finding(f) -> ReportFinding:
    status = FindingStatus.LIKELY if f.strong else FindingStatus.SUSPICIOUS
    return ReportFinding(
        title=f.title,
        type=f.vuln_type,
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=status,
        status_reason=(
            "Untrusted request input reaches this sink (static dataflow). Confirm no "
            "sanitizer neutralises it; verify dynamically where possible."
        ),
        endpoint=f"{f.relpath}:{f.line}",
        description=f"User-controlled input flows into {f.sink}.",
        impact="An attacker-controlled value reaching this sink can lead to "
        f"{f.vuln_type.replace('_', ' ')}.",
        evidence=f"{f.sink} — {f.evidence}",
        validation_method="static taint analysis (source → sink)",
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:taint"],
    )


def _sink_finding(f) -> ReportFinding:
    # Definite misconfigurations (weak hash, disabled TLS) are "likely"; dangerous
    # sinks whose exploitability depends on input reachability are "suspicious".
    status = FindingStatus.LIKELY if f.definite else FindingStatus.SUSPICIOUS
    reason = (
        "Definite insecure usage."
        if f.definite
        else "Dangerous sink; confirm untrusted input cannot reach it (taint/dynamic)."
    )
    return ReportFinding(
        title=f.title,
        type=f.category,
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=status,
        status_reason=reason,
        endpoint=f"{f.relpath}:{f.line}",
        evidence=f"{f.rule} — {f.evidence}",
        validation_method="static dangerous-sink analysis",
        owasp_category=f.owasp,
        cwe=f.cwe,
        remediation=f.remediation,
        sources=["static:sinks"],
    )


def _route_finding(f) -> ReportFinding:
    r = f.route
    return ReportFinding(
        title=f.title,
        type="missing_function_level_authorization",
        severity=Severity(f.severity),
        confidence=f.confidence,
        status=FindingStatus.SUSPICIOUS,
        status_reason=f.reason,
        endpoint=f"{r.relpath}:{r.line}",
        parameter=f"{r.method} {r.path}",
        description=(
            f"The {r.framework} handler '{r.handler or r.path}' serves {r.method} "
            f"{r.path} with no authorization dependency, decorator or middleware detected."
        ),
        impact="If unprotected, callers could reach this action without authorization.",
        evidence=f"{r.method} {r.path} — handler {r.handler or '(anonymous)'}",
        validation_method="static route/authorization analysis",
        owasp_category="A01:2021 Broken Access Control",
        cwe="CWE-862",
        remediation=(
            "Apply an authorization check to this endpoint (an auth dependency, decorator "
            "or route middleware), or confirm a global guard covers it."
        ),
        sources=["static:routes"],
    )


def scan_to_report_context(
    result: ScanResult, *, repo_label: str | None = None, demo: bool = False
) -> ReportContext:
    name = repo_label or os.path.basename(os.path.abspath(result.root)) or result.root
    now = datetime.now(UTC)
    try:
        who = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can raise on odd environments
        who = "unknown"
    if demo:
        who = "SecureAgent demo (bundled sample application)"

    findings = [_secret_finding(f) for f in result.ordered_secrets]
    findings += [_misconfig_finding(f) for f in result.ordered_misconfig_findings]
    findings += [_logging_finding(f) for f in result.ordered_logging_findings]
    findings += [_logic_finding(f) for f in result.ordered_logic_findings]
    findings += [_idor_finding(f) for f in result.ordered_idor_findings]
    findings += [_taint_finding(f) for f in result.ordered_taint_findings]
    findings += [_dependency_finding(f) for f in result.ordered_dependency_findings]
    findings += [_sink_finding(f) for f in result.ordered_sink_findings]
    findings += [_route_finding(f) for f in result.ordered_route_findings]

    endpoints = sorted({f"{r.method} {r.path}" for r in result.routes})
    limitations = [
        "Static source analysis only; no live target was tested in this report.",
        "Authorization may be enforced by global middleware this analyser cannot observe, "
        "so unprotected-endpoint findings require manual confirmation.",
    ]
    if result.stats.truncated:
        limitations.append("The scan was truncated by a size/file limit; coverage is partial.")

    return ReportContext(
        audit_id=str(uuid.uuid4()),
        audit_status="completed",
        is_demo=demo,
        started_at=now,
        completed_at=now,
        generated_at=now,
        target_name=name,
        target_url=(
            "(bundled demo sample — a deliberately vulnerable fake application)"
            if demo
            else "(static source scan — no live target)"
        ),
        authorized_by=who,
        authorized_at=now,
        authorization_statement=AUTHORIZATION_STATEMENT,
        methodology=[
            "Read-only source ingestion (vendored/VCS/binary excluded)",
            "Hardcoded-secret detection (redacted)",
            "Dependency inventory matched against the OSV vulnerability database",
            "Dangerous-sink detection (deserialization, injection, weak crypto, TLS)",
            "Taint analysis (untrusted input reaching injection/SSRF/path sinks)",
            "Object-level authorization (IDOR) analysis",
            "Security misconfiguration detection (debug, CORS, JWT, CSRF, autoescape)",
            "Logging & monitoring checks (sensitive data in logs, swallowed exceptions)",
            "Route and authorization extraction",
            "Business-logic checks (client-trusted values, mass assignment)",
        ],
        technologies=sorted({d.ecosystem for d in result.dependencies}),
        endpoints=endpoints,
        findings=findings,
        limitations=limitations,
    )
