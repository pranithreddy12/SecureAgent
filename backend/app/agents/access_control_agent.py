"""AccessControlAgent: two-account BOLA check on owner-listed object URLs (read-only GETs)."""

from __future__ import annotations

import asyncio

from app.agents.safe_validation_agent import _ctx
from app.tools.access_check import check_object, parse_config, summarize, to_findings
from app.tools.http import rate_sleep
from app.workflows.state import AuditState


async def run(state: AuditState) -> dict:
    cfg = parse_config(state.get("access_check"))
    if cfg is None:
        return {"stage_summary": {"skipped": "No test accounts were supplied for this audit."}}
    if state.get("demo_mode"):
        return {"stage_summary": {"skipped": "Demo mode sends no requests."}}
    ctx = _ctx(state)
    last: list[float | None] = [None]

    def pause() -> None:
        last[0] = rate_sleep(last[0])

    def run_all():
        out = []
        for url in cfg.urls:
            pause()
            out.append(check_object(url, cfg, ctx, pause=pause))
        return out

    outcomes = await asyncio.to_thread(run_all)
    findings, results = to_findings(outcomes)
    return {
        "suspected_findings": [*(state.get("suspected_findings") or []), *findings],
        "validation_results": [*(state.get("validation_results") or []), *results],
        "stage_summary": summarize(outcomes),
    }
