"""Source audits: create, run and persist (ADR-011).

The runner is a plain coroutine over an ``AsyncSession`` so it is testable inline; production
schedules it as an asyncio task with its own session (see ``app.api.audits``).
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import AuditStatus, LogStatus
from app.core.paths import PathNotAllowed, confine_to_roots
from app.models import AuditLog, SecurityAudit, SecurityReport, User, Vulnerability
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
    *,
    agent: str = AGENT,
) -> None:
    db.add(AuditLog(audit_id=audit_id, agent=agent, action=action, status=status, message=message))
    await db.flush()
    logger.info("[AUDIT-%s] %s: %s", audit_id, action, message)


class AIUnavailable(Exception):
    """AI review was requested but the server has no LLM key configured."""


class TooManyActiveAudits(Exception):
    """The user already has MAX_CONCURRENT_SCANS audits queued or running."""


async def create_source_audit(
    db: AsyncSession,
    user: User,
    *,
    path: str,
    label: str | None,
    exclude: list[str],
    project_id: uuid.UUID | None = None,
    authorization_statement: str = AUTHORIZATION_STATEMENT,
    authorized_at: datetime | None = None,
    ai_review: bool = False,
) -> SecurityAudit:
    """Queue a source audit for an already-confined directory."""
    if ai_review and not get_settings().llm_api_key:
        raise AIUnavailable
    limit = get_settings().max_concurrent_scans
    active = await db.scalar(
        select(func.count())
        .select_from(SecurityAudit)
        .where(
            SecurityAudit.user_id == user.id,
            SecurityAudit.status.in_([AuditStatus.QUEUED, AuditStatus.RUNNING]),
        )
    )
    if (active or 0) >= limit:
        raise TooManyActiveAudits

    audit = SecurityAudit(
        user_id=user.id,
        audit_type="source",
        source_project_id=project_id,
        source_label=((label or Path(path).name) or "source")[:255],
        source_path=path,
        authorization_statement=authorization_statement,
        authorized_at=authorized_at or _utcnow(),
        status=AuditStatus.QUEUED,
        progress=0,
        stage_state={
            "exclude": exclude,
            **(
                {"ai": {"consent": True, "consented_at": _utcnow().isoformat(), "limit": 15}}
                if ai_review
                else {}
            ),
        },
    )
    db.add(audit)
    await db.flush()
    await _log(db, audit.id, "queued", "Source audit queued (authorization confirmed).")
    if ai_review:
        await _log(
            db,
            audit.id,
            "ai_consent",
            "AI review requested: code excerpts of the most severe findings will be sent to "
            "the configured LLM provider.",
        )
    await db.commit()
    return audit


async def create_source_audit_from_request(
    db: AsyncSession, user: User, data: SourceAuditCreate
) -> SecurityAudit:
    """Ad-hoc audit of a path: confine it to SOURCE_ROOTS, then queue it."""
    roots = get_settings().source_roots
    if not roots:
        raise SourceAuditsDisabled
    try:
        resolved = confine_to_roots(data.path, roots)
    except PathNotAllowed as exc:
        raise SourcePathRejected(str(exc)) from None
    if not resolved.is_dir():
        raise SourcePathRejected("path is not a directory")
    return await create_source_audit(
        db,
        user,
        path=str(resolved),
        label=data.label,
        exclude=data.exclude,
        ai_review=data.ai_review,
    )


async def run_source_audit(db: AsyncSession, audit_id: uuid.UUID) -> None:
    """Run the audit pipeline (LangGraph, ADR-016). Never raises; failures are recorded."""
    from app.pipeline.context import Ctx
    from app.pipeline.graph import run_pipeline

    audit = await db.get(SecurityAudit, audit_id)
    if audit is None or audit.status is not AuditStatus.QUEUED or not audit.source_path:
        return
    try:
        await run_pipeline(Ctx(db=db, audit_id=audit_id))
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


async def finding_counts(db: AsyncSession, audit_id: uuid.UUID) -> dict[str, int]:
    rows = await db.execute(
        select(Vulnerability.severity, func.count())
        .where(Vulnerability.audit_id == audit_id)
        .group_by(Vulnerability.severity)
    )
    return {sev.value: n for sev, n in rows.all()}


class AuditNotRetryable(Exception):
    """Only a failed source audit can be retried."""


async def reset_for_retry(
    db: AsyncSession, audit: SecurityAudit, *, resume: bool = False
) -> SecurityAudit:
    """Re-queue a failed audit.

    ``resume=False`` (default) starts from a clean slate. ``resume=True`` keeps the artifacts of
    stages that completed and re-runs from the failed stage -- the source is *not* re-read for
    completed stages, so use it for transient failures, not after editing the code.

    Either way the original request (path, exclude patterns, authorization) is kept: a retry
    re-runs the *same* authorized analysis, it does not widen it.
    """
    if audit.audit_type != "source" or audit.status is not AuditStatus.FAILED:
        raise AuditNotRetryable
    state = dict(audit.stage_state or {})
    if resume:
        for name, entry in list(state.items()):
            if isinstance(entry, dict) and entry.get("error"):
                state[name] = {**entry, "error": None, "completed_at": None}
        audit.stage_state = state
    else:
        await db.execute(delete(Vulnerability).where(Vulnerability.audit_id == audit.id))
        await db.execute(delete(SecurityReport).where(SecurityReport.audit_id == audit.id))
        audit.stage_state = {"exclude": list(state.get("exclude", []))}
        audit.started_at = None
    audit.status = AuditStatus.QUEUED
    audit.current_stage = None
    audit.progress = 0
    audit.error_message = None
    audit.completed_at = None
    await _log(
        db,
        audit.id,
        "retry",
        "Audit re-queued; resuming from the failed stage." if resume else "Audit re-queued.",
    )
    await db.commit()
    return audit


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
