"""Pydantic contracts for the live-audit pipeline (agent I/O)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from app.core.enums import FindingStatus, Severity


class TargetScope(BaseModel):
    allowed_hosts: list[str] = []
    path_prefixes: list[str] = ["/"]


class ReconEndpoint(BaseModel):
    url: str
    method: str = "GET"
    status: int | None = None


class ReconForm(BaseModel):
    action: str
    method: str = "GET"
    fields: list[str] = []


class ReconResult(BaseModel):
    target: str
    technologies: list[str] = []
    endpoints: list[ReconEndpoint] = []
    api_endpoints: list[str] = []
    forms: list[ReconForm] = []
    parameters: list[str] = []
    headers: dict[str, str] = {}
    interesting_paths: list[str] = []
    notes: list[str] = []


class RawToolAlert(BaseModel):
    source: str
    name: str
    url: str
    parameter: str | None = None
    severity: str = "informational"
    description: str = ""
    evidence: str = ""
    cwe: str | None = None
    cve: str | None = None
    cvss: dict[str, Any] | None = None
    extra: dict[str, Any] = {}


class SuspectedFinding(BaseModel):
    id: str
    title: str
    type: str
    endpoint: str
    parameter: str | None = None
    severity: Severity = Severity.INFORMATIONAL
    confidence: float = Field(0.4, ge=0, le=1)
    description: str = ""
    evidence: str = ""
    owasp_category: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: dict[str, Any] | None = None
    sources: list[str] = []
    remediation: str | None = None


class ValidationResult(BaseModel):
    finding_id: str
    validated: bool | None
    confidence: float = Field(0.0, ge=0, le=1)
    evidence: str = ""
    validation_method: str
    risk_notes: str = ""


class FinalFinding(SuspectedFinding):
    status: FindingStatus
    status_reason: str
    validation_result: ValidationResult | None = None
    impact: str | None = None


class StageError(BaseModel):
    stage: str
    message: str


class ReportMeta(BaseModel):
    summary: str = ""
    html_chars: int = 0


GateResult = Literal["ok", "fail"]
