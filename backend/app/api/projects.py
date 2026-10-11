"""Source project endpoints (ADR-016): register, authorize, audit, delete -- all owner-scoped."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select

from app.api.audits import Launcher, get_launcher
from app.api.deps import CurrentUser, DbSession
from app.models import SecurityAudit, SourceAuthorization, SourceProject
from app.schemas.audit import AuditOut
from app.schemas.project import (
    AuthorizationOut,
    AuthorizeRequest,
    ProjectAudit,
    ProjectCreate,
    ProjectDetail,
    ProjectOut,
)
from app.services import audit_service, project_service

router = APIRouter(prefix="/projects", tags=["projects"])


async def _owned(db: DbSession, user: CurrentUser, project_id: uuid.UUID) -> SourceProject:
    project = await project_service.owned_project(db, user, project_id)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Project not found")
    return project


def _http(exc: project_service.ProjectError) -> HTTPException:
    return HTTPException(exc.status_code, exc.detail)


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
async def create_project(data: ProjectCreate, db: DbSession, user: CurrentUser):
    try:
        return await project_service.create_project(db, user, data)
    except project_service.ProjectError as exc:
        raise _http(exc) from None


@router.get("", response_model=list[ProjectOut])
async def list_projects(db: DbSession, user: CurrentUser):
    rows = await db.scalars(
        select(SourceProject)
        .where(SourceProject.user_id == user.id)
        .order_by(SourceProject.created_at.desc())
    )
    return list(rows)


@router.get("/{project_id}", response_model=ProjectDetail)
async def get_project(project_id: uuid.UUID, db: DbSession, user: CurrentUser):
    project = await _owned(db, user, project_id)
    history = await db.scalars(
        select(SourceAuthorization)
        .where(SourceAuthorization.project_id == project.id)
        .order_by(SourceAuthorization.timestamp.desc())
        .limit(20)
    )
    count = await db.scalar(
        select(func.count())
        .select_from(SecurityAudit)
        .where(SecurityAudit.source_project_id == project.id)
    )
    detail = ProjectDetail.model_validate(project)
    detail.authorization_history = [AuthorizationOut.model_validate(r) for r in history]
    detail.audit_count = count or 0
    return detail


@router.post("/{project_id}/authorize", response_model=AuthorizationOut)
async def authorize_project(
    project_id: uuid.UUID, data: AuthorizeRequest, db: DbSession, user: CurrentUser
):
    project = await _owned(db, user, project_id)
    if not data.confirmed:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Authorization must be explicitly confirmed."
        )
    return await project_service.set_authorization(db, user, project, True)


@router.post("/{project_id}/revoke", response_model=AuthorizationOut)
async def revoke_project(project_id: uuid.UUID, db: DbSession, user: CurrentUser):
    project = await _owned(db, user, project_id)
    return await project_service.set_authorization(db, user, project, False)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: uuid.UUID, db: DbSession, user: CurrentUser) -> None:
    project = await _owned(db, user, project_id)
    await db.delete(project)
    await db.commit()


@router.post("/{project_id}/audits", response_model=AuditOut, status_code=status.HTTP_202_ACCEPTED)
async def start_project_audit(
    project_id: uuid.UUID,
    data: ProjectAudit,
    db: DbSession,
    user: CurrentUser,
    launch: Annotated[Launcher, Depends(get_launcher)],
):
    project = await _owned(db, user, project_id)
    try:
        audit = await project_service.start_audit(db, user, project, data)
    except project_service.ProjectError as exc:
        raise _http(exc) from None
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


@router.get("/{project_id}/audits", response_model=list[AuditOut])
async def list_project_audits(project_id: uuid.UUID, db: DbSession, user: CurrentUser):
    project = await _owned(db, user, project_id)
    rows = await db.scalars(
        select(SecurityAudit)
        .where(SecurityAudit.source_project_id == project.id, SecurityAudit.user_id == user.id)
        .order_by(SecurityAudit.created_at.desc())
    )
    return list(rows)
