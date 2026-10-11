import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, timestamp_col, utcnow, uuid_pk

if TYPE_CHECKING:
    from app.models.user import User


class SourceProject(Base):
    """A registered source directory (the source-only counterpart of a target, ADR-016)."""

    __tablename__ = "source_projects"
    __table_args__ = (UniqueConstraint("user_id", "path", name="uq_source_projects_user_id_path"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    path: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    authorization_confirmed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    authorization_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = timestamp_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, server_default=func.now()
    )

    user: Mapped["User"] = relationship()
    authorizations: Mapped[list["SourceAuthorization"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", passive_deletes=True
    )


class SourceAuthorization(Base):
    """Append-only trail of authorization confirmations and revocations for a project."""

    __tablename__ = "source_authorizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("source_projects.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    confirmed: Mapped[bool] = mapped_column(Boolean)
    statement: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = timestamp_col()

    project: Mapped["SourceProject"] = relationship(back_populates="authorizations")
