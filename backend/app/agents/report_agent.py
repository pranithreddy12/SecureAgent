"""Build ReportContext from pipeline state and render HTML."""

from __future__ import annotations

from datetime import UTC, datetime

from app.core.enums import FindingStatus, Severity
from app.reports.renderer import render_html
from app.schemas.pipeline import FinalFinding, ReconResult
from app.schemas.report import ReportContext, ReportFinding, TimelineEntry
from app.workflows.state import AuditState


def findings_to_report(rows: list[FinalFinding]) -> list[ReportFinding]:
    out = []
    for f in rows:
        out.append(
            ReportFinding(
                title=f.title,
                type=f.type,
                severity=f.severity if isinstance(f.severity, Severity) else Severity(f.severity),
                confidence=f.confidence,
                status=f.status if isinstance(f.status, FindingStatus) else FindingStatus(f.status),
                status_reason=f.status_reason,
                endpoint=f.endpoint,
                parameter=f.parameter,
                description=f.description,
                impact=f.impact,
                evidence=f.evidence,
                validation_method=(
                    f.validation_result.validation_method if f.validation_result else None
                ),
                owasp_category=f.owasp_category,
                cwe=f.cwe,
                cve=f.cve,
                cvss=f.cvss,  # type: ignore[arg-type]
                remediation=f.remediation,
                sources=f.sources,
            )
        )
    return out


def build_context(state: AuditState) -> ReportContext:
    recon = ReconResult.model_validate(
        state.get("reconnaissance_results") or {"target": state.get("target_url")}
    )
    finals = [FinalFinding.model_validate(f) for f in state.get("final_findings") or []]
    rejected = [FinalFinding.model_validate(f) for f in state.get("rejected_findings") or []]
    errors = state.get("errors") or []
    limitations = [
        "Scanner output is potential until safe validation confirms it.",
        "CVE identifiers are copied from tool metadata only; none are invented.",
        "Safe validation never attempts exploitation, authentication bypass or data extraction.",
    ]
    if state.get("demo_mode"):
        limitations.append(
            "DEMO / SIMULATED SECURITY AUDIT — fixture data; no live target was contacted."
        )
    for err in errors:
        limitations.append(f"Tool limitation: {err.get('message', err)}")
    timestamps = state.get("timestamps") or {}
    timeline = [
        TimelineEntry(
            stage=stage,
            status="completed" if (timestamps.get(stage) or {}).get("completed") else "started",
            started_at=_parse((timestamps.get(stage) or {}).get("started")),
            completed_at=_parse((timestamps.get(stage) or {}).get("completed")),
        )
        for stage in timestamps
    ]
    ctx = ReportContext(
        audit_id=state.get("audit_id") or "",
        audit_status="completed",
        is_demo=bool(state.get("demo_mode")),
        started_at=_parse((timestamps.get("authorization_check") or {}).get("started")),
        completed_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
        target_name=state.get("target_name") or state.get("target_url") or "target",
        target_url=state.get("target_url") or "",
        target_description=state.get("target_description"),
        scope=state.get("target_scope") or {},
        authorized_by=state.get("authorized_by") or "unknown",
        authorized_at=_parse(state.get("authorized_at")),
        authorization_statement=state.get("authorization_statement") or "",
        methodology=[
            "Authorization and target-safety gates",
            "Same-scope reconnaissance",
            "OWASP ZAP, Nuclei and passive header checks (potential findings)",
            "Safe (non-destructive) validation",
            "Deterministic validator and professional report",
        ],
        technologies=recon.technologies,
        endpoints=[e.url if hasattr(e, "url") else str(e) for e in recon.endpoints],
        api_endpoints=list(recon.api_endpoints),
        forms=[f.action if hasattr(f, "action") else str(f) for f in recon.forms],
        parameters=list(recon.parameters),
        interesting_paths=list(recon.interesting_paths),
        findings=findings_to_report(finals + rejected),
        limitations=limitations,
        timeline=timeline,
    )
    ctx.executive_summary = ctx.default_executive_summary()
    if state.get("demo_mode"):
        ctx.executive_summary = "DEMO / SIMULATED SECURITY AUDIT. " + ctx.executive_summary
    return ctx


def _parse(value: object):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


async def run(state: AuditState) -> dict:
    ctx = build_context(state)
    html = render_html(ctx)
    return {
        "report_html": html,
        "report_summary": ctx.executive_summary or "",
        "current_stage": "report_generation",
        "progress": 95,
    }
