"""Turn a static ScanResult into the shared ReportContext (Phase 13) for HTML/PDF."""

from __future__ import annotations

import getpass
import os
import uuid
from datetime import UTC, datetime

from app.analysis.scanner import ScanResult
from app.models.enums import FindingStatus, Severity
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


def scan_to_report_context(result: ScanResult, *, repo_label: str | None = None) -> ReportContext:
    name = repo_label or os.path.basename(os.path.abspath(result.root)) or result.root
    now = datetime.now(UTC)
    try:
        who = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can raise on odd environments
        who = "unknown"

    findings = [_secret_finding(f) for f in result.ordered_secrets]
    findings += [_dependency_finding(f) for f in result.ordered_dependency_findings]
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
        is_demo=False,
        started_at=now,
        completed_at=now,
        generated_at=now,
        target_name=name,
        target_url="(static source scan — no live target)",
        authorized_by=who,
        authorized_at=now,
        authorization_statement=AUTHORIZATION_STATEMENT,
        methodology=[
            "Read-only source ingestion (vendored/VCS/binary excluded)",
            "Hardcoded-secret detection (redacted)",
            "Dependency inventory matched against the OSV vulnerability database",
            "Route and authorization extraction",
        ],
        technologies=sorted({d.ecosystem for d in result.dependencies}),
        endpoints=endpoints,
        findings=findings,
        limitations=limitations,
    )
