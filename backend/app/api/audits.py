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
from app.models import AuditLog, SecurityAudit, SecurityReport, Vulnerability
from app.schemas.audit import (
    AuditDetail,
    AuditOut,
    FindingOut,
    LogOut,
    SourceAuditCreate,
)
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
        audit = await audit_service.create_source_audit(db, user, data)
    except audit_service.SourceAuditsDisabled:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Source audits are disabled: the server has no SOURCE_ROOTS configured.",
        ) from None
    except audit_service.SourcePathRejected as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
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
    return detail


@router.get("/{audit_id}/findings", response_model=list[FindingOut])
async def list_findings(audit_id: uuid.UUID, db: DbSession, user: CurrentUser):
    await _owned_audit(db, user, audit_id)
    rows = await db.scalars(
        select(Vulnerability)
        .where(Vulnerability.audit_id == audit_id)
        .order_by(Vulnerability.severity, Vulnerability.endpoint)
    )
    return list(rows)


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
