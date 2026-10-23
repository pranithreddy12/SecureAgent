"""Fixture-backed tool adapters for DEMO mode (ADR-004). No network I/O."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from app.schemas.pipeline import RawToolAlert, ReconResult, SuspectedFinding, ValidationResult
from app.tools.normalize import to_suspected
from app.tools.passive import passive_alerts


@lru_cache
def _load(name: str) -> object:
    root = resources.files("app.demo.fixtures")
    return json.loads((root / name).read_text(encoding="utf-8"))


def demo_recon() -> ReconResult:
    return ReconResult.model_validate(_load("recon.json"))


def demo_alerts() -> list[RawToolAlert]:
    recon = demo_recon()
    fixture = [RawToolAlert.model_validate(a) for a in _load("alerts.json")]
    return fixture + passive_alerts(recon)


def demo_validation(finding: SuspectedFinding) -> ValidationResult:
    # Configuration issues in the fixture are treated as still present; reflection is
    # left inconclusive so demo never claims a confirmed XSS without a live probe.
    blob = f"{finding.type} {finding.title}".lower()
    if any(k in blob for k in ("header", "hsts", "csp", "clickjack", "cookie")):
        return ValidationResult(
            finding_id=finding.id,
            validated=True,
            confidence=0.8,
            evidence="DEMO fixture: header still absent (no network request).",
            validation_method="demo_header_refetch",
        )
    return ValidationResult(
        finding_id=finding.id,
        validated=None,
        confidence=finding.confidence,
        evidence="DEMO fixture: no safe live probe was performed.",
        validation_method="demo_no_probe",
        risk_notes="DEMO / SIMULATED SECURITY AUDIT",
    )


def demo_suspected(audit_id: str) -> list[SuspectedFinding]:
    return to_suspected(audit_id, demo_alerts())
