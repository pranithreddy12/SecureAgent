"""Shared state and helpers for pipeline agents."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, TypedDict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SecurityAudit, Vulnerability
from app.schemas.report import AIReview, CvssScore, ReportFinding


class PipelineState(TypedDict, total=False):
    """LangGraph state. Artifacts live in the database; this only carries control flow."""

    failed: bool


class StageFailure(Exception):
    """An agent failed; ``message`` is safe to show (no filesystem paths)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class Ctx:
    db: AsyncSession
    audit_id: uuid.UUID
    notes: dict[str, Any] = field(default_factory=dict)

    async def audit(self) -> SecurityAudit:
        audit = await self.db.get(SecurityAudit, self.audit_id)
        if audit is None:
            raise StageFailure("The audit no longer exists.")
        return audit

    async def finding_rows(self) -> list[Vulnerability]:
        rows = await self.db.scalars(
            select(Vulnerability)
            .where(Vulnerability.audit_id == self.audit_id)
            .order_by(Vulnerability.endpoint, Vulnerability.title)
        )
        return list(rows)


def to_report_finding(row: Vulnerability) -> ReportFinding:
    return ReportFinding(
        title=row.title,
        type=row.type,
        severity=row.severity,
        confidence=row.confidence,
        status=row.status,
        status_reason=row.status_reason,
        endpoint=row.endpoint,
        parameter=row.parameter,
        description=row.description,
        impact=row.impact,
        evidence=row.evidence,
        validation_method=(row.validation_result or {}).get("method"),
        owasp_category=row.owasp_category,
        cwe=row.cwe,
        cve=row.cve,
        cvss=CvssScore(**row.cvss) if row.cvss else None,
        remediation=row.remediation,
        sources=list(row.sources or []),
        ai_review=(
            AIReview(**(row.validation_result or {})["ai_review"])
            if (row.validation_result or {}).get("ai_review")
            else None
        ),
    )
