"""Live-target endpoints (ADR-044): register, authorize, run and read live audits.

Mirrors ``app/api/projects.py``'s shape exactly -- owner-scoped CRUD, an authorize step, a start-
audit action. Live audits persist into the same ``SecurityAudit``/``Vulnerability`` tables the
source pipeline uses, so ``/api/audits/{id}`` and its findings/logs/report endpoints work for a
live audit unchanged; this file only adds how a live audit gets *created*.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.api.audits import Launcher, get_launcher
from app.api.deps import CurrentUser, DbSession
from app.models import SecurityAudit, Target
from app.schemas.audit import AuditOut
from app.schemas.target import (
    AuditReadiness,
    AuthorizationOut,
    AuthorizeRequest,
    TargetCreate,
    TargetOut,
    TargetUpdate,
)
from app.security.target_validation import InvalidTargetURL
from app.services import audit_service, authorization_service, live_audit_service, target_service

router = APIRouter(prefix="/targets", tags=["targets"])


def _http(exc: Exception) -> HTTPException:
    if isinstance(exc, target_service.TargetNotFound):
        return HTTPException(status.HTTP_404_NOT_FOUND, "Target not found")
    if isinstance(exc, target_service.TargetLimitReached):
        return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Target limit reached")
    if isinstance(exc, target_service.DuplicateTarget):
        return HTTPException(status.HTTP_409_CONFLICT, "You already have a target with this URL")
    if isinstance(exc, target_service.TargetHasActiveAudit):
        return HTTPException(
            status.HTTP_409_CONFLICT, "An audit is queued or running for this target"
        )
    if isinstance(exc, InvalidTargetURL):
        return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    return HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
async def create_target(data: TargetCreate, db: DbSession, user: CurrentUser):
    try:
        return await target_service.create_target(db, user, data)
    except Exception as exc:
        raise _http(exc) from None


@router.get("", response_model=list[TargetOut])
async def list_targets(db: DbSession, user: CurrentUser):
    return await target_service.list_targets(db, user)


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(target_id: uuid.UUID, db: DbSession, user: CurrentUser):
    try:
        return await target_service.get_target(db, user, target_id)
    except target_service.TargetNotFound:
        raise _http(target_service.TargetNotFound()) from None


@router.patch("/{target_id}", response_model=TargetOut)
async def update_target(target_id: uuid.UUID, data: TargetUpdate, db: DbSession, user: CurrentUser):
    try:
        return await target_service.update_target(db, user, target_id, data)
    except Exception as exc:
        raise _http(exc) from None


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: uuid.UUID, db: DbSession, user: CurrentUser) -> None:
    try:
        await target_service.delete_target(db, user, target_id)
    except Exception as exc:
        raise _http(exc) from None


@router.post("/{target_id}/revalidate", response_model=TargetOut)
async def revalidate_target(target_id: uuid.UUID, db: DbSession, user: CurrentUser):
    try:
        return await target_service.revalidate(db, user, target_id)
    except target_service.TargetNotFound:
        raise _http(target_service.TargetNotFound()) from None


@router.get("/{target_id}/readiness", response_model=AuditReadiness)
async def target_readiness(target_id: uuid.UUID, db: DbSession, user: CurrentUser):
    target = await _owned(db, user, target_id)
    return authorization_service.readiness(target)


async def _owned(db: DbSession, user: CurrentUser, target_id: uuid.UUID) -> Target:
    try:
        return await target_service.get_target(db, user, target_id)
    except target_service.TargetNotFound:
        raise _http(target_service.TargetNotFound()) from None


@router.post("/{target_id}/authorize", response_model=AuthorizationOut)
async def authorize_target(
    target_id: uuid.UUID, data: AuthorizeRequest, db: DbSession, user: CurrentUser
):
    target = await _owned(db, user, target_id)
    if not data.confirmed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Authorization must be explicitly confirmed."
        )
    try:
        return await authorization_service.record_authorization(db, user, target, confirmed=True)
    except authorization_service.AuthorizationNotConfirmed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Authorization was not confirmed."
        ) from None


@router.post("/{target_id}/audits", response_model=AuditOut, status_code=status.HTTP_202_ACCEPTED)
async def start_target_audit(
    target_id: uuid.UUID,
    db: DbSession,
    user: CurrentUser,
    launch: Annotated[Launcher, Depends(get_launcher)],
):
    target = await _owned(db, user, target_id)
    try:
        audit = await live_audit_service.create_live_audit(db, user, target)
    except live_audit_service.TargetNotReady as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None
    except audit_service.TooManyActiveAudits:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many audits are already queued or running. Wait for one to finish.",
        ) from None
    await launch(audit.id)
    return audit


@router.get("/{target_id}/audits", response_model=list[AuditOut])
async def list_target_audits(target_id: uuid.UUID, db: DbSession, user: CurrentUser):
    target = await _owned(db, user, target_id)
    rows = await db.scalars(
        select(SecurityAudit)
        .where(SecurityAudit.target_id == target.id, SecurityAudit.user_id == user.id)
        .order_by(SecurityAudit.created_at.desc())
    )
    return list(rows)
