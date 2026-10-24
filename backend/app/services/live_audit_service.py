"""Live-target audits: create and run the live-agent pipeline (ADR-044).

Wires the live agents (``app/agents/*``) into a real LangGraph graph with **per-stage DB
persistence** -- mirroring ``app/pipeline/graph.py``'s pattern for the source pipeline exactly,
rather than ``workflows/audit_graph.py``'s own ``build_graph()``, which keeps progress in memory
only and would leave the UI showing nothing until the whole run finished (a live scan can take
minutes). The gate logic and agents themselves are reused unchanged.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")

from langgraph.graph import END, START, StateGraph  # noqa: E402

from app.agents import (  # noqa: E402
    reconnaissance_agent,
    report_agent,
    safe_validation_agent,
    validator_agent,
    vulnerability_scanner_agent,
)
from app.analysis.baseline import fingerprint  # noqa: E402
from app.core.enums import AuditStatus, LogStatus  # noqa: E402
from app.models import SecurityAudit, SecurityReport, Target, Vulnerability  # noqa: E402
from app.schemas.pipeline import FinalFinding  # noqa: E402
from app.schemas.target import AUTHORIZATION_STATEMENT  # noqa: E402
from app.services import audit_service, authorization_service  # noqa: E402
from app.workflows.audit_graph import (  # noqa: E402
    PROGRESS,
    _after_gate,
    _after_scan,
    attack_surface_processing,
    authorization_check,
    target_validation,
)
from app.workflows.state import AuditState  # noqa: E402

logger = logging.getLogger("secureagent.live_audit")

STAGE_LABELS = {
    "authorization_check": "Check authorization",
    "target_validation": "Validate target safety",
    "reconnaissance": "Map the live application",
    "attack_surface_processing": "Process the attack surface",
    "vulnerability_scanning": "Scan for vulnerabilities (ZAP + Nuclei + passive)",
    "safe_validation": "Safely validate findings (non-destructive)",
    "validator": "Reduce false positives",
    "report_generation": "Generate report",
}


def _now() -> datetime:
    return datetime.now(UTC)


class TargetNotReady(Exception):
    """The target failed its readiness check (authorization/safety) at audit-creation time."""


async def create_live_audit(db: AsyncSession, user, target: Target) -> SecurityAudit:
    ready = authorization_service.readiness(target)
    if not ready.auditable:
        raise TargetNotReady("; ".join(ready.reasons))
    limit_check = await db.scalar(
        select(func.count())
        .select_from(SecurityAudit)
        .where(
            SecurityAudit.user_id == user.id,
            SecurityAudit.status.in_([AuditStatus.QUEUED, AuditStatus.RUNNING]),
        )
    )
    from app.core.config import get_settings

    if (limit_check or 0) >= get_settings().max_concurrent_scans:
        raise audit_service.TooManyActiveAudits
    audit = SecurityAudit(
        user_id=user.id,
        audit_type="live",
        target_id=target.id,
        source_label=target.name[:255],
        authorization_statement=AUTHORIZATION_STATEMENT,
        authorized_at=target.authorization_timestamp or _now(),
        status=AuditStatus.QUEUED,
        progress=0,
    )
    db.add(audit)
    await db.flush()
    await audit_service._log(db, audit.id, "queued", "Live audit queued (target authorized).")
    await db.commit()
    return audit


def _wrap(db: AsyncSession, audit: SecurityAudit, stage: str, agent: str, fn):
    """Persist progress/log around an agent node, the way ``app/pipeline/graph.py`` does for the
    source pipeline -- the agent functions themselves (``app/agents/*``) are unchanged."""
    label = STAGE_LABELS.get(stage, stage)

    async def run(state: AuditState) -> dict:
        audit.current_stage = stage
        audit.progress = PROGRESS.get(stage, audit.progress)
        await audit_service._log(db, audit.id, "started", label, agent=agent)
        await db.commit()
        try:
            update = await fn(state)
        except Exception as exc:  # noqa: BLE001 - a live agent must never crash the audit
            logger.exception("[LIVE-AUDIT-%s] %s failed", audit.id, stage)
            await audit_service._log(
                db,
                audit.id,
                "failed",
                f"{label} failed unexpectedly ({type(exc).__name__}).",
                LogStatus.ERROR,
                agent=agent,
            )
            return {"gate_failed": True, "fail_reason": f"{label} failed unexpectedly."}
        if update.get("gate_failed"):
            await audit_service._log(
                db,
                audit.id,
                "stopped",
                update.get("fail_reason") or label,
                LogStatus.WARNING,
                agent=agent,
            )
        else:
            # Same shape the frontend already reads for the source pipeline's stage checklist
            # (``audit.stage_state[key].completed_at``) -- no UI change needed for this part.
            stage_state = dict(audit.stage_state or {})
            stage_state[stage] = {"completed_at": _now().isoformat()}
            audit.stage_state = stage_state
            await audit_service._log(
                db, audit.id, "completed", label, LogStatus.SUCCESS, agent=agent
            )
        await db.commit()
        return update

    return run


def _build_graph(db: AsyncSession, audit: SecurityAudit):
    g = StateGraph(AuditState)
    g.add_node(
        "authorization_check", _wrap(db, audit, "authorization_check", "gate", authorization_check)
    )
    g.add_node(
        "target_validation", _wrap(db, audit, "target_validation", "gate", target_validation)
    )
    g.add_node(
        "reconnaissance",
        _wrap(db, audit, "reconnaissance", "reconnaissance-agent", reconnaissance_agent.run),
    )
    g.add_node(
        "attack_surface_processing",
        _wrap(
            db,
            audit,
            "attack_surface_processing",
            "reconnaissance-agent",
            attack_surface_processing,
        ),
    )
    g.add_node(
        "vulnerability_scanning",
        _wrap(
            db, audit, "vulnerability_scanning", "scanner-agent", vulnerability_scanner_agent.run
        ),
    )
    g.add_node(
        "safe_validation",
        _wrap(db, audit, "safe_validation", "validation-agent", safe_validation_agent.run),
    )
    g.add_node("validator", _wrap(db, audit, "validator", "validator-agent", validator_agent.run))
    g.add_node(
        "report_generation",
        _wrap(db, audit, "report_generation", "report-agent", report_agent.run),
    )
    g.add_edge(START, "authorization_check")
    g.add_conditional_edges(
        "authorization_check", _after_gate, {"ok": "target_validation", "fail": END}
    )
    g.add_conditional_edges("target_validation", _after_gate, {"ok": "reconnaissance", "fail": END})
    g.add_edge("reconnaissance", "attack_surface_processing")
    g.add_edge("attack_surface_processing", "vulnerability_scanning")
    g.add_conditional_edges(
        "vulnerability_scanning",
        _after_scan,
        {"validate": "safe_validation", "report": "report_generation"},
    )
    g.add_edge("safe_validation", "validator")
    g.add_edge("validator", "report_generation")
    g.add_edge("report_generation", END)
    return g.compile()


async def _persist_findings(db: AsyncSession, audit_id: uuid.UUID, state: AuditState) -> None:
    finals = [FinalFinding.model_validate(f) for f in state.get("final_findings") or []]
    seen: dict[str, int] = {}
    for f in finals:
        fp = fingerprint(f)
        seen[fp] = seen.get(fp, 0) + 1
        unique = fp if seen[fp] == 1 else f"{fp}-{seen[fp]}"
        db.add(
            Vulnerability(
                audit_id=audit_id,
                fingerprint=unique,
                title=f.title[:255],
                type=f.type[:80],
                endpoint=f.endpoint[:2048],
                parameter=(f.parameter or None) and f.parameter[:255],
                severity=f.severity,
                confidence=f.confidence,
                status=f.status,
                status_reason=f.status_reason,
                sources=list(f.sources),
                description=f.description,
                impact=f.impact,
                evidence=f.evidence,
                validation_result=f.validation_result.model_dump() if f.validation_result else None,
                owasp_category=f.owasp_category,
                cwe=f.cwe,
                cve=f.cve,
                cvss=f.cvss,
                remediation=f.remediation,
            )
        )
    html = state.get("report_html")
    if html:
        db.add(
            SecurityReport(
                audit_id=audit_id, summary=state.get("report_summary") or "", report_html=html
            )
        )
    await db.flush()


async def fail_interrupted(db: AsyncSession) -> int:
    """Startup sweep: live audits left queued/running by a dead process can never finish (the
    runner task does not survive a restart), so mark them failed instead of showing them forever.
    Mirrors ``audit_service.fail_interrupted`` for ``audit_type == 'source'``."""
    rows = await db.scalars(
        select(SecurityAudit).where(
            SecurityAudit.audit_type == "live",
            SecurityAudit.status.in_([AuditStatus.QUEUED, AuditStatus.RUNNING]),
        )
    )
    audits = list(rows)
    for audit in audits:
        audit.status = AuditStatus.FAILED
        audit.error_message = "Interrupted by a server restart. Start the audit again."
        audit.completed_at = _now()
        await audit_service._log(db, audit.id, "interrupted", audit.error_message, LogStatus.ERROR)
    await db.commit()
    return len(audits)


async def run_live_audit(db: AsyncSession, audit_id: uuid.UUID) -> None:
    """Run the live pipeline end to end. Never raises; failures are recorded (ADR-044)."""
    audit = await db.get(SecurityAudit, audit_id)
    if audit is None or audit.status is not AuditStatus.QUEUED or not audit.target_id:
        return
    target = await db.get(Target, audit.target_id)
    if target is None:
        await audit_service._fail(db, audit_id, "The target no longer exists.")
        return
    audit.status = AuditStatus.RUNNING
    audit.started_at = audit.started_at or _now()
    await db.commit()

    initial: AuditState = {
        "audit_id": str(audit_id),
        "user_id": str(audit.user_id),
        "target_id": str(target.id),
        "target_url": target.url,
        "target_name": target.name,
        "target_description": target.description,
        "authorization_status": bool(target.authorization_confirmed),
        "authorization_statement": audit.authorization_statement or "",
        "authorized_at": (target.authorization_timestamp or _now()).isoformat(),
        "authorized_by": "",
        "target_scope": dict(target.scope or {}),
        "demo_mode": False,
        "cancelled": False,
    }
    try:
        final_state = await _build_graph(db, audit).ainvoke(initial)
    except Exception as exc:  # noqa: BLE001 - the runner must always record a terminal state
        logger.exception("[LIVE-AUDIT-%s] unexpected failure", audit_id)
        await audit_service._fail(
            db, audit_id, f"Audit failed unexpectedly ({type(exc).__name__})."
        )
        return

    audit = await db.get(SecurityAudit, audit_id)  # reload: _wrap() committed along the way
    if audit is None:
        return
    if final_state.get("gate_failed"):
        audit.status = AuditStatus.FAILED
        audit.error_message = (final_state.get("fail_reason") or "Audit stopped.")[:500]
        audit.completed_at = _now()
        await db.commit()
        return
    await _persist_findings(db, audit_id, final_state)
    audit.status = AuditStatus.COMPLETED
    audit.progress = 100
    audit.current_stage = None
    audit.completed_at = _now()
    await audit_service._log(db, audit.id, "completed", "Live audit completed.", LogStatus.SUCCESS)
    await db.commit()
