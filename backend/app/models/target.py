import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, str_enum, timestamp_col, utcnow, uuid_pk
from app.models.enums import TargetStatus

if TYPE_CHECKING:
    from app.models.audit import SecurityAudit
    from app.models.user import User


class Target(Base):
    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("user_id", "url", name="uq_targets_user_id_url"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    url: Mapped[str] = mapped_column(String(2048))
    description: Mapped[str | None] = mapped_column(Text)
    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    authorization_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[TargetStatus] = mapped_column(
        str_enum(TargetStatus, "target_status"),
        default=TargetStatus.PENDING,
        server_default="pending",
    )
    # {"allowed_hosts": [...], "path_prefixes": [...]}
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    validation_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = timestamp_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="targets")
    authorization_records: Mapped[list["AuthorizationRecord"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )
    audits: Mapped[list["SecurityAudit"]] = relationship(
        back_populates="target", cascade="all, delete-orphan", passive_deletes=True
    )


class AuthorizationRecord(Base):
    """Append-only trail of authorization confirmations."""

    __tablename__ = "authorization_records"

    id: Mapped[uuid.UUID] = uuid_pk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    confirmed: Mapped[bool] = mapped_column(Boolean)
    statement: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = timestamp_col()
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")

    target: Mapped["Target"] = relationship(back_populates="authorization_records")
