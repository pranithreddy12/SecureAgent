"""Deterministic false-positive reduction, status, OWASP/CWE mapping. LLM cannot raise status."""

from __future__ import annotations

from app.core.enums import FindingStatus
from app.schemas.pipeline import FinalFinding, SuspectedFinding, ValidationResult
from app.workflows.state import AuditState


def decide(finding: SuspectedFinding, validation: ValidationResult | None) -> FinalFinding:
    sources = finding.sources
    if validation and validation.validated is True:
        status, reason = (
            FindingStatus.CONFIRMED,
            "Safe validation reproduced the issue with evidence.",
        )
        conf = max(finding.confidence, validation.confidence)
    elif validation and validation.validated is False:
        status, reason = (
            FindingStatus.FALSE_POSITIVE,
            "Safe validation did not reproduce the alert.",
        )
        conf = min(finding.confidence, 0.3)
    elif validation is None or validation.validated is None:
        if len(sources) >= 2:
            status, reason = (
                FindingStatus.LIKELY,
                "Multiple independent scanners reported this; validation was inconclusive.",
            )
        elif finding.confidence >= 0.6:
            status, reason = (
                FindingStatus.LIKELY,
                "Single scanner with moderate confidence; not re-tested.",
            )
        elif "informational" in finding.severity.value:
            status, reason = FindingStatus.INFORMATIONAL, "No security impact on its own."
        else:
            status, reason = (
                FindingStatus.SUSPICIOUS,
                "Single low-confidence source without a safe validation strategy.",
            )
        conf = finding.confidence
        if finding.severity.value == "informational" and status is FindingStatus.SUSPICIOUS:
            status, reason = (
                FindingStatus.INFORMATIONAL,
                "Informational scanner output; no impact on its own.",
            )
    else:
        status, reason, conf = (
            FindingStatus.SUSPICIOUS,
            "Insufficient evidence.",
            finding.confidence,
        )

    return FinalFinding(
        **finding.model_dump(exclude={"confidence"}),
        status=status,
        status_reason=reason,
        confidence=min(1.0, conf),
        validation_result=validation,
        impact=finding.description[:500] or None,
    )


async def run(state: AuditState) -> dict:
    validations = {
        v["finding_id"]: ValidationResult.model_validate(v)
        for v in (state.get("validation_results") or [])
    }
    finals: list[FinalFinding] = []
    rejected: list[FinalFinding] = []
    for raw in state.get("suspected_findings") or []:
        finding = SuspectedFinding.model_validate(raw)
        decided = decide(finding, validations.get(finding.id))
        if decided.status is FindingStatus.FALSE_POSITIVE:
            rejected.append(decided)
        else:
            finals.append(decided)
    return {
        "final_findings": [f.model_dump(mode="json") for f in finals],
        "rejected_findings": [f.model_dump(mode="json") for f in rejected],
        "current_stage": "validator",
        "progress": 85,
    }
