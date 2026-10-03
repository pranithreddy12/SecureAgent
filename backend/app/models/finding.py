import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, str_enum, timestamp_col, utcnow, uuid_pk
from app.models.enums import FindingStatus, Severity

if TYPE_CHECKING:
    from app.models.audit import SecurityAudit


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        # Idempotency: a retried stage upserts instead of duplicating findings.
        UniqueConstraint("audit_id", "fingerprint", name="uq_vulnerabilities_audit_fingerprint"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_audits.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(255))
    type: Mapped[str] = mapped_column(String(80))
    endpoint: Mapped[str] = mapped_column(String(2048))
    parameter: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, "severity"), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[FindingStatus] = mapped_column(
        str_enum(FindingStatus, "finding_status"), index=True
    )
    status_reason: Mapped[str | None] = mapped_column(Text)
    sources: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    description: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    validation_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    owasp_category: Mapped[str | None] = mapped_column(String(80), index=True)
    cwe: Mapped[str | None] = mapped_column(String(20))
    # NULL means "Not applicable / no specific CVE identified." Never invented.
    cve: Mapped[str | None] = mapped_column(String(40))
    # {"score": float, "vector": str, "version": str}; NULL means "CVSS not determined."
    cvss: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = timestamp_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, server_default=func.now()
    )

    audit: Mapped["SecurityAudit"] = relationship(back_populates="vulnerabilities")
