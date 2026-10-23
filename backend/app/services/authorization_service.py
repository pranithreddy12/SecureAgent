"""Authorization records and audit-readiness (docs/security-model.md §1)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.enums import TargetStatus
from app.models import AuthorizationRecord, Target, User
from app.schemas.target import AUTHORIZATION_STATEMENT, AuditReadiness
from app.security.target_validation import InvalidTargetURL, check_url
from app.services import target_service


class AuthorizationNotConfirmed(Exception):
    pass


async def record_authorization(
    db: AsyncSession, user: User, target: Target, *, confirmed: bool
) -> AuthorizationRecord:
    if not confirmed:
        raise AuthorizationNotConfirmed
    now = datetime.now(UTC)
    row = AuthorizationRecord(
        target_id=target.id,
        user_id=user.id,
        confirmed=True,
        statement=AUTHORIZATION_STATEMENT,
        timestamp=now,
        scope=dict(target.scope or {}),
    )
    target.authorization_confirmed = True
    target.authorization_timestamp = now
    db.add(row)
    await db.commit()
    await db.refresh(row)
    await db.refresh(target)
    return row


async def latest_record(db: AsyncSession, target: Target) -> AuthorizationRecord | None:
    return await db.scalar(
        select(AuthorizationRecord)
        .where(AuthorizationRecord.target_id == target.id)
        .order_by(AuthorizationRecord.timestamp.desc())
        .limit(1)
    )


def readiness(target: Target) -> AuditReadiness:
    reasons: list[str] = []
    if not target.authorization_confirmed or target.authorization_timestamp is None:
        reasons.append("Authorization has not been confirmed for the current URL and scope.")
    if target.status is TargetStatus.REJECTED:
        reasons.append(target.validation_message or "Target failed safety validation.")
    settings = get_settings()
    try:
        check = check_url(
            target.url,
            allow_private=settings.allow_private_targets,
            allowlist=settings.target_allowlist,
        )
    except InvalidTargetURL as exc:
        reasons.append(str(exc))
        check = None
    else:
        if not check.allowed:
            reasons.append(check.reason)
    # Deduplicate while preserving order.
    uniq: list[str] = []
    for r in reasons:
        if r and r not in uniq:
            uniq.append(r)
    return AuditReadiness(auditable=not uniq, reasons=uniq)


async def require_ready(db: AsyncSession, user: User, target_id) -> Target:
    target = await target_service.get_target(db, user, target_id)
    ready = readiness(target)
    if not ready.auditable:
        raise AuthorizationNotConfirmed("; ".join(ready.reasons))
    return target
