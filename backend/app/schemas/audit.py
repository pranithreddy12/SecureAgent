"""Request/response models for audits (ADR-011)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import AuditStatus, FindingStatus, LogStatus, Severity
from app.schemas.report import AttackChain

AUTHORIZATION_STATEMENT = (
    "I confirm that I own this source code or am explicitly authorized to analyse it, and that "
    "SecureAgent may read it for a security audit."
)


class SourceAuditCreate(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    label: str | None = Field(default=None, max_length=255)
    authorization_confirmed: bool
    exclude: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("exclude")
    @classmethod
    def _short_patterns(cls, v: list[str]) -> list[str]:
        if any(not p or len(p) > 200 for p in v):
            raise ValueError("exclude patterns must be 1-200 characters")
        return v


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    audit_type: str
    source_label: str | None
    status: AuditStatus
    current_stage: str | None
    progress: int
    is_demo: bool
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime
    authorized_at: datetime | None


class AuditDetail(AuditOut):
    stage_state: dict[str, Any]
    finding_counts: dict[str, int] = {}
    total_findings: int = 0
    attack_chains: list[AttackChain] = []
    application_model: dict[str, list[str]] = {}
    validation_notes: list[str] = []


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    title: str
    type: str
    endpoint: str
    parameter: str | None
    severity: Severity
    confidence: float
    status: FindingStatus
    status_reason: str | None
    description: str | None
    impact: str | None
    evidence: str | None
    owasp_category: str | None
    cwe: str | None
    cve: str | None
    cvss: dict[str, Any] | None
    remediation: str | None
    sources: list[str]


class LogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent: str
    action: str
    status: LogStatus
    message: str
    timestamp: datetime
