"""Shared live-audit state. JSON-serialisable so each stage can be persisted."""

from __future__ import annotations

from typing import Any, TypedDict


class AuditState(TypedDict, total=False):
    audit_id: str
    user_id: str
    target_id: str
    target_url: str
    target_name: str
    target_description: str | None
    authorization_status: bool
    authorization_statement: str
    authorized_at: str | None
    authorized_by: str
    target_scope: dict[str, Any]
    demo_mode: bool
    cancelled: bool
    gate_failed: bool
    fail_reason: str
    reconnaissance_results: dict[str, Any]
    technologies: list[str]
    endpoints: list[Any]
    scanner_results: list[dict[str, Any]]
    suspected_findings: list[dict[str, Any]]
    validation_results: list[dict[str, Any]]
    rejected_findings: list[dict[str, Any]]
    final_findings: list[dict[str, Any]]
    report_html: str
    report_summary: str
    current_stage: str
    progress: int
    errors: list[dict[str, str]]
    timestamps: dict[str, dict[str, str | None]]
