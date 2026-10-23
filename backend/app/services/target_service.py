"""Target CRUD + ownership. No network I/O."""

from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import AuditStatus, TargetStatus, UserRole
from app.models import SecurityAudit, Target, User
from app.schemas.target import TargetCreate, TargetUpdate
from app.security.target_validation import InvalidTargetURL, check_url, normalize_url


class TargetNotFound(Exception):
    pass


class TargetLimitReached(Exception):
    pass


class DuplicateTarget(Exception):
    pass


class TargetHasActiveAudit(Exception):
    pass


def _owned(query, user: User):
    if user.role is UserRole.ADMIN:
        return query
    return query.where(Target.user_id == user.id)


async def get_target(db: AsyncSession, user: User, target_id: uuid.UUID) -> Target:
    target = await db.get(Target, target_id)
    if target is None or (user.role is not UserRole.ADMIN and target.user_id != user.id):
        raise TargetNotFound
    return target


async def list_targets(db: AsyncSession, user: User) -> list[Target]:
    q = _owned(select(Target), user).order_by(Target.created_at.desc())
    return list(await db.scalars(q))


def _scope_for(url: str, path_prefixes: list[str] | None) -> dict:
    host = urlsplit(url).hostname or ""
    prefixes = path_prefixes or ["/"]
    return {"allowed_hosts": [host], "path_prefixes": prefixes}


def _apply_safety(target: Target) -> None:
    settings = get_settings()
    try:
        check = check_url(
            target.url,
            allow_private=settings.allow_private_targets,
            allowlist=settings.target_allowlist,
        )
    except InvalidTargetURL as exc:
        target.status = TargetStatus.REJECTED
        target.validation_message = str(exc)
        return
    target.url = check.url
    if check.allowed:
        target.status = TargetStatus.VALIDATED
        target.validation_message = "URL passed safety checks."
    else:
        target.status = TargetStatus.REJECTED
        target.validation_message = check.reason


async def create_target(db: AsyncSession, user: User, data: TargetCreate) -> Target:
    settings = get_settings()
    n = await db.scalar(select(func.count()).select_from(Target).where(Target.user_id == user.id))
    if (n or 0) >= settings.max_targets_per_user:
        raise TargetLimitReached
    try:
        url = normalize_url(str(data.url))
    except InvalidTargetURL as exc:
        raise InvalidTargetURL(str(exc)) from exc
    target = Target(
        user_id=user.id,
        name=data.name,
        url=url,
        description=data.description,
        scope=_scope_for(url, data.path_prefixes),
        status=TargetStatus.PENDING,
    )
    _apply_safety(target)
    db.add(target)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateTarget from exc
    await db.refresh(target)
    return target


def _scope_changed(target: Target, new_scope: dict) -> bool:
    return target.scope != new_scope


async def update_target(
    db: AsyncSession, user: User, target_id: uuid.UUID, data: TargetUpdate
) -> Target:
    target = await get_target(db, user, target_id)
    url_changed = False
    if data.name is not None:
        target.name = data.name
    if data.description is not None:
        target.description = data.description
    if data.url is not None:
        try:
            url = normalize_url(str(data.url))
        except InvalidTargetURL as exc:
            raise InvalidTargetURL(str(exc)) from exc
        if url != target.url:
            target.url = url
            url_changed = True
    prefixes = (
        data.path_prefixes if data.path_prefixes is not None else target.scope.get("path_prefixes")
    )
    new_scope = _scope_for(target.url, prefixes)
    reset_auth = url_changed or _scope_changed(target, new_scope)
    target.scope = new_scope
    if reset_auth:
        target.authorization_confirmed = False
        target.authorization_timestamp = None
    _apply_safety(target)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise DuplicateTarget from exc
    await db.refresh(target)
    return target


async def delete_target(db: AsyncSession, user: User, target_id: uuid.UUID) -> None:
    target = await get_target(db, user, target_id)
    active = await db.scalar(
        select(func.count())
        .select_from(SecurityAudit)
        .where(
            SecurityAudit.target_id == target.id,
            SecurityAudit.status.in_([AuditStatus.QUEUED, AuditStatus.RUNNING]),
        )
    )
    if active:
        raise TargetHasActiveAudit
    await db.delete(target)
    await db.commit()


async def revalidate(db: AsyncSession, user: User, target_id: uuid.UUID) -> Target:
    target = await get_target(db, user, target_id)
    _apply_safety(target)
    await db.commit()
    await db.refresh(target)
    return target
