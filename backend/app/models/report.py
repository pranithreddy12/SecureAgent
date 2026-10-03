import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, timestamp_col, uuid_pk

if TYPE_CHECKING:
    from app.models.audit import SecurityAudit


class SecurityReport(Base):
    __tablename__ = "security_reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_audits.id", ondelete="CASCADE"), unique=True
    )
    summary: Mapped[str] = mapped_column(Text)
    report_html: Mapped[str] = mapped_column(Text)
    # PDF file path under REPORTS_DIR; NULL until rendered.
    report_path: Mapped[str | None] = mapped_column(String(1024))
    generated_at: Mapped[datetime] = timestamp_col()

    audit: Mapped["SecurityAudit"] = relationship(back_populates="report")
