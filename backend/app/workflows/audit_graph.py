"""Live-audit LangGraph (ADR-001). Routing is deterministic; the LLM never chooses the next node."""

from __future__ import annotations

from datetime import UTC, datetime

from app.agents import (
    reconnaissance_agent,
    report_agent,
    safe_validation_agent,
    validator_agent,
    vulnerability_scanner_agent,
)
from app.core.config import get_settings
from app.security.target_validation import InvalidTargetURL, check_url
from app.workflows.graphlib import load_state_graph
from app.workflows.state import AuditState

StateGraph, START, END = load_state_graph()

PROGRESS = {
    "authorization_check": 5,
    "target_validation": 10,
    "reconnaissance": 30,
    "attack_surface_processing": 35,
    "vulnerability_scanning": 60,
    "safe_validation": 75,
    "validator": 85,
    "report_generation": 95,
    "persist_results": 100,
}


def _stamp(state: AuditState, stage: str, *, done: bool = False) -> dict:
    stamps = dict(state.get("timestamps") or {})
    entry = dict(stamps.get(stage) or {})
    now = datetime.now(UTC).isoformat()
    if not entry.get("started"):
        entry["started"] = now
    if done:
        entry["completed"] = now
    stamps[stage] = entry
    return {
        "timestamps": stamps,
        "current_stage": stage,
        "progress": PROGRESS.get(stage, state.get("progress", 0)),
    }


async def authorization_check(state: AuditState) -> dict:
    update = _stamp(state, "authorization_check", done=True)
    if not state.get("authorization_status"):
        update.update(gate_failed=True, fail_reason="Authorization is missing or stale.")
    return update


async def target_validation(state: AuditState) -> dict:
    update = _stamp(state, "target_validation", done=True)
    if state.get("demo_mode"):
        return update
    settings = get_settings()
    try:
        check = check_url(
            state["target_url"],
            allow_private=settings.allow_private_targets,
            allowlist=settings.target_allowlist,
        )
    except InvalidTargetURL as exc:
        update.update(gate_failed=True, fail_reason=str(exc))
        return update
    if not check.allowed:
        update.update(gate_failed=True, fail_reason=check.reason)
    else:
        update["target_url"] = check.url
    return update


async def reconnaissance(state: AuditState) -> dict:
    started = _stamp(state, "reconnaissance")
    result = await reconnaissance_agent.run({**state, **started})
    result.update(_stamp({**state, **started, **result}, "reconnaissance", done=True))
    return result


async def attack_surface_processing(state: AuditState) -> dict:
    recon = state.get("reconnaissance_results") or {}
    endpoints = recon.get("endpoints") or state.get("endpoints") or []
    urls = []
    for item in endpoints:
        if isinstance(item, dict):
            urls.append(item.get("url"))
        else:
            urls.append(getattr(item, "url", item))
    update = _stamp(state, "attack_surface_processing", done=True)
    update["endpoints"] = [u for u in urls if u]
    return update


async def vulnerability_scanning(state: AuditState) -> dict:
    started = _stamp(state, "vulnerability_scanning")
    result = await vulnerability_scanner_agent.run({**state, **started})
    result.update(_stamp({**state, **started, **result}, "vulnerability_scanning", done=True))
    return result


async def safe_validation(state: AuditState) -> dict:
    started = _stamp(state, "safe_validation")
    result = await safe_validation_agent.run({**state, **started})
    result.update(_stamp({**state, **started, **result}, "safe_validation", done=True))
    return result


async def validator(state: AuditState) -> dict:
    started = _stamp(state, "validator")
    result = await validator_agent.run({**state, **started})
    result.update(_stamp({**state, **started, **result}, "validator", done=True))
    return result


async def report_generation(state: AuditState) -> dict:
    started = _stamp(state, "report_generation")
    result = await report_agent.run({**state, **started})
    result.update(_stamp({**state, **started, **result}, "report_generation", done=True))
    return result


async def persist_results(state: AuditState) -> dict:
    return _stamp(state, "persist_results", done=True) | {"progress": 100}


def _after_gate(state: AuditState) -> str:
    return "fail" if state.get("gate_failed") else "ok"


def _after_scan(state: AuditState) -> str:
    return "validate" if state.get("suspected_findings") else "report"


def build_graph():
    g = StateGraph(AuditState)
    g.add_node("authorization_check", authorization_check)
    g.add_node("target_validation", target_validation)
    g.add_node("reconnaissance", reconnaissance)
    g.add_node("attack_surface_processing", attack_surface_processing)
    g.add_node("vulnerability_scanning", vulnerability_scanning)
    g.add_node("safe_validation", safe_validation)
    g.add_node("validator", validator)
    g.add_node("report_generation", report_generation)
    g.add_node("persist_results", persist_results)
    g.add_edge(START, "authorization_check")
    g.add_conditional_edges(
        "authorization_check", _after_gate, {"ok": "target_validation", "fail": END}
    )
    g.add_conditional_edges("target_validation", _after_gate, {"ok": "reconnaissance", "fail": END})
    g.add_edge("reconnaissance", "attack_surface_processing")
    g.add_edge("attack_surface_processing", "vulnerability_scanning")
    g.add_conditional_edges(
        "vulnerability_scanning",
        _after_scan,
        {"validate": "safe_validation", "report": "report_generation"},
    )
    g.add_edge("safe_validation", "validator")
    g.add_edge("validator", "report_generation")
    g.add_edge("report_generation", "persist_results")
    g.add_edge("persist_results", END)
    return g.compile()


_compiled = None


def compiled_graph():
    global _compiled
    if _compiled is None:
        _compiled = build_graph()
    return _compiled
