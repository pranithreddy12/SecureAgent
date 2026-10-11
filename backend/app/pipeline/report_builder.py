"""Assemble a report context from persisted pipeline artifacts."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.authz_matrix import build_matrix
from app.analysis.routes import PRIVILEGED_PATH, Route
from app.models import ReconnaissanceResult, SecurityAudit, User, Vulnerability
from app.pipeline.context import to_report_finding
from app.schemas.audit import AUTHORIZATION_STATEMENT
from app.schemas.report import (
    AttackChain,
    MatrixGroupView,
    MatrixRoute,
    ReportContext,
    TimelineEntry,
)

AGENT_LABELS = {
    "authorization": "Authorization and scope gate",
    "reconnaissance": "Source reconnaissance (application model)",
    "scanner": "Static analysis (secrets, dependencies, injection, access control, business logic)",
    "safe_validation": "Fix verification (patch parses, re-scan shows the finding gone)",
    "validator": "Rule-based validation (test/example/dev-only code reclassified)",
    "ai_validator": "AI review of findings (opt-in second opinion; never changes status)",
    "correlation": "Attack-chain correlation",
    "ai_narrative": "AI-written executive summary (opt-in; from structured findings only)",
    "report": "Report generation",
}


def _dt(value: Any) -> datetime | None:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None


def _timeline(state: dict[str, Any]) -> list[TimelineEntry]:
    entries = []
    for name, label in AGENT_LABELS.items():
        entry = state.get(name)
        if not isinstance(entry, dict):
            continue
        status = (
            "failed"
            if entry.get("error")
            else "completed"
            if entry.get("completed_at") or name == "report"  # the report is being built now
            else "running"
        )
        entries.append(
            TimelineEntry(
                stage=label,
                status=status,
                started_at=_dt(entry.get("started_at")),
                completed_at=_dt(entry.get("completed_at")),
                note=entry.get("note"),
            )
        )
    return entries


async def build_context(
    db: AsyncSession,
    audit: SecurityAudit,
    recon: ReconnaissanceResult,
    rows: list[Vulnerability],
) -> ReportContext:
    owner = await db.get(User, audit.user_id)
    state = audit.stage_state or {}
    raw = recon.raw_result or {}
    model: dict[str, list[str]] = raw.get("model", {})
    routes = [Route(**r) for r in raw.get("routes", [])]
    findings = [to_report_finding(r) for r in rows]

    matrix = [
        MatrixGroupView(
            resource=g.resource,
            guarded=g.guarded,
            total=len(g.routes),
            routes=[
                MatrixRoute(
                    method=r.method,
                    path=r.path,
                    handler=r.handler or "",
                    guarded=r.protected,
                    guard=r.guard,
                    location=f"{r.relpath}:{r.line}",
                )
                for r in g.routes
            ],
        )
        for g in build_matrix(routes)
    ]
    chains = [AttackChain.model_validate(c) for c in state.get("attack_chains", [])]
    limitations = [
        "Static source analysis only; no live target was tested in this report.",
        "Authorization may be enforced by global middleware this analyser cannot observe, "
        "so unprotected-endpoint findings require manual confirmation.",
        "Dependency advisories (OSV) are not queried by server-side audits.",
    ]
    narrative = (state.get("ai") or {}).get("narrative") or {}
    now = datetime.now(UTC)
    return ReportContext(
        audit_id=str(audit.id),
        audit_status="completed",
        started_at=audit.started_at,
        completed_at=now,
        generated_at=now,
        target_name=audit.source_label or "source audit",
        target_url="(static source audit — no live target)",
        authorized_by=owner.email if owner else "unknown",
        authorized_at=audit.authorized_at,
        authorization_statement=audit.authorization_statement or AUTHORIZATION_STATEMENT,
        methodology=[label for name, label in AGENT_LABELS.items() if name in state],
        technologies=list(recon.technologies or []),
        endpoints=list(recon.endpoints or []),
        api_endpoints=list(recon.api_endpoints or []),
        parameters=list(model.get("parameters", [])),
        interesting_paths=sorted(
            {f"{r.method} {r.path}" for r in routes if PRIVILEGED_PATH.search(r.path)}
        ),
        outbound_hosts=list(model.get("outbound_hosts", [])),
        environment_variables=list(model.get("environment_variables", [])),
        validation_notes=list(state.get("validation_notes", [])),
        executive_summary=narrative.get("text") or None,
        executive_summary_source=(f"AI ({narrative['model']})" if narrative.get("text") else None),
        findings=findings,
        attack_chains=chains,
        authorization_matrix=matrix,
        limitations=limitations,
        timeline=_timeline(state),
    )
