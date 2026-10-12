"""Audit endpoints (ADR-011): start a source audit, follow it, read findings, logs and report."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.core.database import get_sessionmaker
from app.core.enums import AuditStatus, FindingStatus
from app.models import AuditLog, SecurityAudit, SecurityReport, Vulnerability
from app.schemas.audit import (
    AuditDetail,
    AuditOut,
    FindingOut,
    LogOut,
    SourceAuditCreate,
    TriageRequest,
)
from app.schemas.report import AttackChain
from app.services import audit_service

router = APIRouter(prefix="/audits", tags=["audits"])

Launcher = Callable[[uuid.UUID], Awaitable[None]]
_background: set[asyncio.Task] = set()  # keep references so tasks are not garbage collected

# The report is generated HTML containing scanned-code excerpts; never let it run scripts.
_REPORT_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:",
    "X-Content-Type-Options": "nosniff",
}


async def _run_with_own_session(audit_id: uuid.UUID) -> None:
    async with get_sessionmaker()() as session:
        await audit_service.run_source_audit(session, audit_id)


async def _launch_in_background(audit_id: uuid.UUID) -> None:
    task = asyncio.create_task(_run_with_own_session(audit_id))
    _background.add(task)
    task.add_done_callback(_background.discard)


def get_launcher() -> Launcher:
    """Dependency so tests can run the audit inline against their own session."""
    return _launch_in_background


async def _owned_audit(db: DbSession, user: CurrentUser, audit_id: uuid.UUID) -> SecurityAudit:
    audit = await db.scalar(
        select(SecurityAudit).where(SecurityAudit.id == audit_id, SecurityAudit.user_id == user.id)
    )
    if audit is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Audit not found")
    return audit


@router.post("/source", response_model=AuditOut, status_code=status.HTTP_202_ACCEPTED)
async def create_source_audit(
    data: SourceAuditCreate,
    db: DbSession,
    user: CurrentUser,
    launch: Annotated[Launcher, Depends(get_launcher)],
):
    if not data.authorization_confirmed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "You must confirm you are authorized to analyse this source code.",
        )
    try:
        audit = await audit_service.create_source_audit_from_request(db, user, data)
    except audit_service.SourceAuditsDisabled:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Source audits are disabled: the server has no SOURCE_ROOTS configured.",
        ) from None
    except audit_service.SourcePathRejected as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except audit_service.AIUnavailable:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "AI review is not configured on this server (no LLM_API_KEY).",
        ) from None
    except audit_service.TooManyActiveAudits:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many audits are already queued or running. Wait for one to finish.",
        ) from None
    await launch(audit.id)
    return audit


@router.post("/{audit_id}/retry", response_model=AuditOut, status_code=status.HTTP_202_ACCEPTED)
async def retry_audit(
    audit_id: uuid.UUID,
    db: DbSession,
    user: CurrentUser,
    launch: Annotated[Launcher, Depends(get_launcher)],
    resume: bool = False,
):
    audit = await _owned_audit(db, user, audit_id)
    try:
        audit = await audit_service.reset_for_retry(db, audit, resume=resume)
    except audit_service.AuditNotRetryable:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Only a failed source audit can be retried."
        ) from None
    await launch(audit.id)
    return audit


@router.get("", response_model=list[AuditOut])
async def list_audits(
    db: DbSession, user: CurrentUser, limit: Annotated[int, Query(ge=1, le=100)] = 50
):
    rows = await db.scalars(
        select(SecurityAudit)
        .where(SecurityAudit.user_id == user.id)
        .order_by(SecurityAudit.created_at.desc())
        .limit(limit)
    )
    return list(rows)


@router.get("/{audit_id}", response_model=AuditDetail)
async def get_audit(audit_id: uuid.UUID, db: DbSession, user: CurrentUser):
    audit = await _owned_audit(db, user, audit_id)
    counts = await audit_service.finding_counts(db, audit.id)
    detail = AuditDetail.model_validate(audit)
    detail.finding_counts = counts
    detail.total_findings = sum(counts.values())
    detail.application_model = (audit.stage_state or {}).get("application_model", {})
    ai = (audit.stage_state or {}).get("ai") or {}
    detail.ai = {
        "enabled": bool(ai.get("consent")),
        "model": ai.get("model"),
        "reviewed": ai.get("reviewed", 0),
        "summary_written": bool((ai.get("narrative") or {}).get("text")),
        "problems": [p for p in (ai.get("validator_problem"), ai.get("summary_problem")) if p],
    }
    detail.validation_notes = (audit.stage_state or {}).get("validation_notes", [])
    detail.attack_chains = [
        AttackChain.model_validate(c) for c in (audit.stage_state or {}).get("attack_chains", [])
    ]
    return detail


@router.get("/{audit_id}/findings", response_model=list[FindingOut])
async def list_findings(audit_id: uuid.UUID, db: DbSession, user: CurrentUser):
    await _owned_audit(db, user, audit_id)
    rows = await db.scalars(
        select(Vulnerability)
        .where(Vulnerability.audit_id == audit_id)
        .order_by(Vulnerability.severity, Vulnerability.endpoint)
    )
    out = []
    for row in rows:
        item = FindingOut.model_validate(row)
        item.ai_review = (row.validation_result or {}).get("ai_review")
        out.append(item)
    return out


@router.patch("/{audit_id}/findings/{finding_id}/triage", response_model=FindingOut)
async def triage_finding(
    audit_id: uuid.UUID,
    finding_id: uuid.UUID,
    data: TriageRequest,
    db: DbSession,
    user: CurrentUser,
):
    """Record the owner's false-positive verdict. Reversible; the original status is kept."""
    audit = await _owned_audit(db, user, audit_id)
    if audit.status is not AuditStatus.COMPLETED:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Findings can be triaged once the audit is done."
        )
    row = await db.scalar(
        select(Vulnerability)
        .join(SecurityAudit, SecurityAudit.id == Vulnerability.audit_id)
        .where(
            Vulnerability.id == finding_id,
            Vulnerability.audit_id == audit.id,
            SecurityAudit.user_id == user.id,
        )
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    vr = dict(row.validation_result or {})
    if data.false_positive:
        if "triage" not in vr:  # keep the first original status across repeated edits
            vr["triage"] = {
                "previous_status": row.status.value,
                "previous_reason": row.status_reason,
            }
        vr["triage"]["by"] = user.email
        vr["triage"]["reason"] = data.reason.strip()
        row.status = FindingStatus.FALSE_POSITIVE
        row.status_reason = f"Marked false positive by {user.email}: {data.reason.strip()}"
    elif "triage" in vr:
        previous = vr.pop("triage")
        row.status = FindingStatus(previous["previous_status"])
        row.status_reason = previous.get("previous_reason")
    row.validation_result = vr
    await db.commit()
    item = FindingOut.model_validate(row)
    item.ai_review = vr.get("ai_review")
    return item


@router.get("/{audit_id}/logs", response_model=list[LogOut])
async def list_logs(audit_id: uuid.UUID, db: DbSession, user: CurrentUser):
    await _owned_audit(db, user, audit_id)
    rows = await db.scalars(
        select(AuditLog).where(AuditLog.audit_id == audit_id).order_by(AuditLog.timestamp)
    )
    return list(rows)


@router.get("/{audit_id}/report")
async def get_report(
    audit_id: uuid.UUID,
    db: DbSession,
    user: CurrentUser,
    format: Annotated[str, Query(pattern="^(html|pdf)$")] = "html",  # noqa: A002
    download: bool = False,
):
    await _owned_audit(db, user, audit_id)
    report = await db.scalar(select(SecurityReport).where(SecurityReport.audit_id == audit_id))
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not generated yet")
    headers = dict(_REPORT_HEADERS)
    if format == "pdf":
        from app.reports.renderer import render_pdf

        try:
            body = await asyncio.to_thread(render_pdf, report.report_html)
        except (ImportError, OSError):
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "PDF rendering is not available on this server"
            ) from None
        headers["Content-Disposition"] = f'attachment; filename="secureagent-{audit_id}.pdf"'
        return Response(body, media_type="application/pdf", headers=headers)
    if download:
        headers["Content-Disposition"] = f'attachment; filename="secureagent-{audit_id}.html"'
    return Response(report.report_html, media_type="text/html; charset=utf-8", headers=headers)
