from __future__ import annotations

from app.demo.adapters import demo_recon
from app.tools.policy import RequestContext
from app.tools.recon_tool import crawl
from app.workflows.state import AuditState


async def run(state: AuditState) -> dict:
    ctx = _ctx(state)
    if state.get("demo_mode"):
        recon = demo_recon()
    else:
        recon = crawl(state["target_url"], ctx)
    return {
        "reconnaissance_results": recon.model_dump(mode="json"),
        "technologies": recon.technologies,
        "endpoints": [e.url if hasattr(e, "url") else e for e in recon.endpoints],
        "current_stage": "reconnaissance",
        "progress": 30,
    }


def _ctx(state: AuditState) -> RequestContext:
    from app.schemas.pipeline import TargetScope

    return RequestContext(
        authorized=bool(state.get("authorization_status")),
        scope=TargetScope.model_validate(state.get("target_scope") or {}),
        demo=bool(state.get("demo_mode")),
        cancelled=bool(state.get("cancelled")),
    )
