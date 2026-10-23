"""SafeValidationAgent — controlled implementation of the PPT Exploitation Agent (ADR-003)."""

from __future__ import annotations

from app.demo.adapters import demo_validation
from app.schemas.pipeline import SuspectedFinding
from app.tools.policy import RequestContext
from app.tools.validation_tool import validate_finding
from app.workflows.state import AuditState


async def run(state: AuditState) -> dict:
    ctx = _ctx(state)
    results = []
    for raw in state.get("suspected_findings") or []:
        finding = SuspectedFinding.model_validate(raw)
        if state.get("demo_mode"):
            result = demo_validation(finding)
        else:
            result = validate_finding(finding, ctx)
        results.append(result.model_dump(mode="json"))
    return {
        "validation_results": results,
        "current_stage": "safe_validation",
        "progress": 75,
    }


def _ctx(state: AuditState) -> RequestContext:
    from app.schemas.pipeline import TargetScope

    return RequestContext(
        authorized=bool(state.get("authorization_status")),
        scope=TargetScope.model_validate(state.get("target_scope") or {}),
        demo=bool(state.get("demo_mode")),
        cancelled=bool(state.get("cancelled")),
    )
