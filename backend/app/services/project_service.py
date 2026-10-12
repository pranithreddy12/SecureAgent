"""Source projects: registration, authorization and audit launch (ADR-016, phases 4-5).

Restrictions enforced here (and tested):
- the directory must be inside ``SOURCE_ROOTS`` (symlinks / ``..`` resolved) and exist;
- at most ``MAX_TARGETS_PER_USER`` projects per user, one project per (user, path);
- an audit can only start for a project with a *current* authorization (a later revocation wins);
- at most ``MAX_CONCURRENT_SCANS`` queued/running audits per user;
- the path is re-confined when the audit starts, so a directory swapped for a symlink later fails.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.paths import PathNotAllowed, confine_to_roots
from app.models import SecurityAudit, SourceAuthorization, SourceProject, User
from app.schemas.audit import AUTHORIZATION_STATEMENT
from app.schemas.project import ProjectAudit, ProjectCreate
from app.services import audit_service


class ProjectError(Exception):
    """Base class; ``status_code`` / ``detail`` map directly to an HTTP response."""

    status_code = 400

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class ProjectsDisabled(ProjectError):
    status_code = 503


class ProjectLimitReached(ProjectError):
    status_code = 409


class DuplicateProject(ProjectError):
    status_code = 409


class NotAuthorized(ProjectError):
    status_code = 403


def _roots() -> list[str]:
    roots = get_settings().audit_roots
    if not roots:
        raise ProjectsDisabled(
            "Source projects are disabled: the server has no SOURCE_ROOTS configured."
        )
    return roots


def confined_dir(path: str, *, uploads: bool = False) -> str:
    """Confine to the mounted source roots; ``uploads`` also allows the (private) upload dir."""
    settings = get_settings()
    _roots()  # raises ProjectsDisabled when nothing is configured
    allowed = settings.audit_roots if uploads else settings.source_roots
    try:
        resolved = confine_to_roots(path, allowed)
    except PathNotAllowed:
        raise ProjectError("path is outside the allowed roots") from None
    if not resolved.is_dir():
        raise ProjectError("path is not a directory")
    if not uploads and settings.upload_dir:
        uploads_root = Path(settings.upload_dir).resolve()
        if resolved == uploads_root or uploads_root in resolved.parents:
            raise ProjectError("path is outside the allowed roots")  # other users' uploads
    return str(resolved)


async def check_limit(db: AsyncSession, user: User) -> None:
    count = await db.scalar(
        select(func.count()).select_from(SourceProject).where(SourceProject.user_id == user.id)
    )
    if (count or 0) >= get_settings().max_targets_per_user:
        raise ProjectLimitReached("Project limit reached for this account.")


async def create_project(
    db: AsyncSession, user: User, data: ProjectCreate, *, uploaded: bool = False
) -> SourceProject:
    path = confined_dir(data.path, uploads=uploaded)
    await check_limit(db, user)
    project = SourceProject(
        user_id=user.id, name=data.name, path=path, description=data.description
    )
    db.add(project)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise DuplicateProject("This directory is already registered.") from None
    return project


async def set_authorization(
    db: AsyncSession, user: User, project: SourceProject, confirmed: bool
) -> SourceAuthorization:
    now = datetime.now(UTC)
    record = SourceAuthorization(
        project_id=project.id,
        user_id=user.id,
        confirmed=confirmed,
        statement=AUTHORIZATION_STATEMENT
        if confirmed
        else "Authorization revoked by the project owner.",
    )
    db.add(record)
    project.authorization_confirmed = confirmed
    project.authorization_timestamp = now if confirmed else None
    await db.commit()
    return record


async def latest_authorization(
    db: AsyncSession, project: SourceProject
) -> SourceAuthorization | None:
    return await db.scalar(
        select(SourceAuthorization)
        .where(SourceAuthorization.project_id == project.id)
        .order_by(SourceAuthorization.timestamp.desc(), SourceAuthorization.id)
        .limit(1)
    )


async def start_audit(
    db: AsyncSession, user: User, project: SourceProject, data: ProjectAudit
) -> SecurityAudit:
    latest = await latest_authorization(db, project)
    if not (project.authorization_confirmed and latest and latest.confirmed):
        raise NotAuthorized("Confirm authorization for this project before auditing it.")
    return await audit_service.create_source_audit(
        db,
        user,
        path=confined_dir(project.path, uploads=True),  # re-confined at launch time
        label=project.name,
        exclude=data.exclude,
        project_id=project.id,
        authorization_statement=latest.statement,
        authorized_at=latest.timestamp,
        ai_review=data.ai_review,
    )


async def owned_project(
    db: AsyncSession, user: User, project_id: uuid.UUID
) -> SourceProject | None:
    return await db.scalar(
        select(SourceProject).where(
            SourceProject.id == project_id, SourceProject.user_id == user.id
        )
    )
