"""Source audits: create, run and persist (ADR-011).

The runner is a plain coroutine over an ``AsyncSession`` so it is testable inline; production
schedules it as an asyncio task with its own session (see ``app.api.audits``).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.baseline import fingerprint
from app.analysis.ingest import IngestError
from app.analysis.intent import IntentError
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.core.config import get_settings
from app.core.enums import AuditStatus, LogStatus
from app.core.paths import PathNotAllowed, confine_to_roots
from app.models import AuditLog, SecurityAudit, SecurityReport, User, Vulnerability
from app.reports.renderer import render_html
from app.schemas.audit import AUTHORIZATION_STATEMENT, SourceAuditCreate

logger = logging.getLogger("secureagent.audit")

AGENT = "static-analysis"


class SourceAuditsDisabled(Exception):
    """No SOURCE_ROOTS configured."""


class SourcePathRejected(Exception):
    """The requested directory is outside the roots or is not a directory."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


async def _log(
    db: AsyncSession,
    audit_id: uuid.UUID,
    action: str,
    message: str,
    status: LogStatus = LogStatus.INFO,
) -> None:
    db.add(AuditLog(audit_id=audit_id, agent=AGENT, action=action, status=status, message=message))
    await db.flush()
    logger.info("[AUDIT-%s] %s: %s", audit_id, action, message)


async def create_source_audit(
    db: AsyncSession, user: User, data: SourceAuditCreate
) -> SecurityAudit:
    roots = get_settings().source_roots
    if not roots:
        raise SourceAuditsDisabled
    try:
        path = confine_to_roots(data.path, roots)
    except PathNotAllowed as exc:
        raise SourcePathRejected(str(exc)) from None
    if not path.is_dir():
        raise SourcePathRejected("path is not a directory")

    now = _utcnow()
    audit = SecurityAudit(
        user_id=user.id,
        audit_type="source",
        source_label=(data.label or path.name)[:255],
        source_path=str(path),
        authorization_statement=AUTHORIZATION_STATEMENT,
        authorized_at=now,
        status=AuditStatus.QUEUED,
        progress=0,
        stage_state={"exclude": data.exclude},
    )
    db.add(audit)
    await db.flush()
    await _log(db, audit.id, "queued", "Source audit queued (authorization confirmed).")
    await db.commit()
    return audit


async def _set_stage(db: AsyncSession, audit: SecurityAudit, stage: str, progress: int) -> None:
    state = dict(audit.stage_state or {})
    state[stage] = {"started_at": _utcnow().isoformat(), "completed_at": None, "error": None}
    audit.stage_state = state
    audit.current_stage = stage
    audit.progress = progress
    await db.commit()


async def _finish_stage(db: AsyncSession, audit: SecurityAudit, stage: str) -> None:
    state = dict(audit.stage_state or {})
    entry = dict(state.get(stage) or {})
    entry["completed_at"] = _utcnow().isoformat()
    state[stage] = entry
    audit.stage_state = state
    await db.commit()


async def run_source_audit(db: AsyncSession, audit_id: uuid.UUID) -> None:
    """Scan, persist findings, render the report. Never raises: failures mark the audit failed."""
    audit = await db.get(SecurityAudit, audit_id)
    if audit is None or audit.status is not AuditStatus.QUEUED or not audit.source_path:
        return
    exclude = list((audit.stage_state or {}).get("exclude", []))
    try:
        audit.status = AuditStatus.RUNNING
        audit.started_at = _utcnow()
        await _set_stage(db, audit, "scan", 10)
        await _log(db, audit.id, "scan_started", "Reading and analysing source files.")
        result = await asyncio.to_thread(
            scan_repo, audit.source_path, check_osv=False, exclude=exclude
        )
        await _log(
            db,
            audit.id,
            "scan_completed",
            f"Analysed {result.stats.files_scanned} files; {result.total_findings} findings.",
        )
        await _finish_stage(db, audit, "scan")

        await _set_stage(db, audit, "persist", 60)
        ctx = scan_to_report_context(result, repo_label=audit.source_label)
        await _persist_findings(db, audit, ctx.findings)
        state = dict(audit.stage_state or {})
        state["attack_chains"] = [c.model_dump(mode="json") for c in ctx.attack_chains]
        audit.stage_state = state
        await _finish_stage(db, audit, "persist")

        await _set_stage(db, audit, "report", 85)
        owner = await db.get(User, audit.user_id)
        ctx = ctx.model_copy(
            update={
                "audit_id": str(audit.id),
                "started_at": audit.started_at,
                "completed_at": _utcnow(),
                "authorized_by": owner.email if owner else "unknown",
                "authorized_at": audit.authorized_at,
                "authorization_statement": audit.authorization_statement or "",
                "target_url": "(static source audit — no live target)",
            }
        )
        html = await asyncio.to_thread(render_html, ctx)
        db.add(
            SecurityReport(
                audit_id=audit.id,
                summary=f"{len(ctx.findings)} findings; {ctx.risk_rating} overall risk.",
                report_html=html,
            )
        )
        await _finish_stage(db, audit, "report")

        audit.status = AuditStatus.COMPLETED
        audit.progress = 100
        audit.current_stage = None
        audit.completed_at = _utcnow()
        await _log(db, audit.id, "completed", "Audit completed.", LogStatus.SUCCESS)
        await db.commit()
    except IntentError:
        await _fail(db, audit_id, "The intent spec (secureagent-intent.json) is invalid.")
    except (IngestError, OSError):
        await _fail(db, audit_id, "The source directory could not be read.")
    except Exception as exc:  # noqa: BLE001 - the runner must always record a terminal state
        logger.exception("[AUDIT-%s] unexpected failure", audit_id)
        await _fail(db, audit_id, f"Audit failed unexpectedly ({type(exc).__name__}).")


async def _fail(db: AsyncSession, audit_id: uuid.UUID, message: str) -> None:
    await db.rollback()
    audit = await db.get(SecurityAudit, audit_id)  # reload after rollback
    if audit is None:
        return
    audit.status = AuditStatus.FAILED
    audit.error_message = message[:500]
    audit.completed_at = _utcnow()
    await _log(db, audit.id, "failed", message[:500], LogStatus.ERROR)
    await db.commit()


async def _persist_findings(db: AsyncSession, audit: SecurityAudit, findings) -> None:
    seen: dict[str, int] = {}
    for f in findings:
        fp = fingerprint(f)
        seen[fp] = seen.get(fp, 0) + 1
        unique = fp if seen[fp] == 1 else f"{fp}-{seen[fp]}"  # same kind/file/title, other line
        db.add(
            Vulnerability(
                audit_id=audit.id,
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
                owasp_category=f.owasp_category,
                cwe=f.cwe,
                cve=f.cve,
                cvss=f.cvss.model_dump() if f.cvss else None,
                remediation=f.remediation,
            )
        )
    await db.flush()
    await _log(db, audit.id, "findings_persisted", f"Stored {len(findings)} findings.")


async def finding_counts(db: AsyncSession, audit_id: uuid.UUID) -> dict[str, int]:
    rows = await db.execute(
        select(Vulnerability.severity, func.count())
        .where(Vulnerability.audit_id == audit_id)
        .group_by(Vulnerability.severity)
    )
    return {sev.value: n for sev, n in rows.all()}


async def fail_interrupted(db: AsyncSession) -> int:
    """Startup sweep: source audits left queued/running by a dead process can never finish
    (runner tasks do not survive a restart), so mark them failed instead of showing them forever."""
    rows = await db.scalars(
        select(SecurityAudit).where(
            SecurityAudit.audit_type == "source",
            SecurityAudit.status.in_([AuditStatus.QUEUED, AuditStatus.RUNNING]),
        )
    )
    audits = list(rows)
    for audit in audits:
        audit.status = AuditStatus.FAILED
        audit.error_message = "Interrupted by a server restart. Start the audit again."
        audit.completed_at = _utcnow()
        await _log(db, audit.id, "interrupted", audit.error_message, LogStatus.ERROR)
    await db.commit()
    return len(audits)
