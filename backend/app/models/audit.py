import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, str_enum, timestamp_col, uuid_pk
from app.models.enums import AuditStatus, LogStatus

if TYPE_CHECKING:
    from app.models.finding import Vulnerability
    from app.models.report import SecurityReport
    from app.models.target import Target


class SecurityAudit(Base):
    __tablename__ = "security_audits"
    __table_args__ = (CheckConstraint("progress BETWEEN 0 AND 100", name="progress_range"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[AuditStatus] = mapped_column(
        str_enum(AuditStatus, "audit_status"),
        default=AuditStatus.QUEUED,
        server_default="queued",
        index=True,
    )
    current_stage: Mapped[str | None] = mapped_column(String(40))
    progress: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # {stage: {"started_at": iso, "completed_at": iso, "error": str | None}}; drives resume.
    stage_state: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = timestamp_col()

    target: Mapped["Target"] = relationship(back_populates="audits")
    recon_result: Mapped["ReconnaissanceResult | None"] = relationship(
        back_populates="audit", cascade="all, delete-orphan", passive_deletes=True
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", passive_deletes=True
    )
    report: Mapped["SecurityReport | None"] = relationship(
        back_populates="audit", cascade="all, delete-orphan", passive_deletes=True
    )
    logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", passive_deletes=True
    )


class ReconnaissanceResult(Base):
    __tablename__ = "reconnaissance_results"

    id: Mapped[uuid.UUID] = uuid_pk()
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_audits.id", ondelete="CASCADE"), unique=True
    )
    technologies: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default="[]")
    endpoints: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default="[]")
    api_endpoints: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default="[]")
    forms: Mapped[list[Any]] = mapped_column(JSONB, default=list, server_default="[]")
    headers: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    raw_result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = timestamp_col()

    audit: Mapped["SecurityAudit"] = relationship(back_populates="recon_result")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = uuid_pk()
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_audits.id", ondelete="CASCADE"), index=True
    )
    agent: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(80))
    status: Mapped[LogStatus] = mapped_column(
        str_enum(LogStatus, "log_status"), default=LogStatus.INFO, server_default="info"
    )
    message: Mapped[str] = mapped_column(Text)
    # "metadata" is reserved on declarative classes; the column keeps the spec name.
    meta: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default="{}"
    )
    timestamp: Mapped[datetime] = timestamp_col(index=True)

    audit: Mapped["SecurityAudit"] = relationship(back_populates="logs")
