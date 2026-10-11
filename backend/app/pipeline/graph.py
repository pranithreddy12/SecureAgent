"""LangGraph workflow wiring the source-only agents (ADR-001, ADR-016).

START -> (first incomplete stage) -> authorization -> reconnaissance -> scanner -> safe_validation
      -> validator -> correlation -> report -> END, with a failed stage routing straight to END.

The graph itself holds no artifacts: each node reads and writes the database, which is what makes
resume-from-failed-stage possible. No LLM is involved and nothing leaves the process.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

# LangChain/LangSmith tracing is opt-in via environment; make the safe default explicit so a stray
# variable in a developer shell cannot ship audit data to a third-party service.
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")

from langgraph.graph import END, START, StateGraph  # noqa: E402

from app.core.enums import AuditStatus, LogStatus  # noqa: E402
from app.pipeline.context import Ctx, PipelineState, StageFailure  # noqa: E402
from app.pipeline.stages import STAGE_NAMES, STAGES, StageSpec  # noqa: E402

logger = logging.getLogger("secureagent.pipeline")


def _now() -> datetime:
    return datetime.now(UTC)


def stage_done(state: dict[str, Any], name: str) -> bool:
    entry = state.get(name)
    return isinstance(entry, dict) and bool(entry.get("completed_at"))


async def _log(ctx: Ctx, agent: str, action: str, message: str, status: LogStatus = LogStatus.INFO):
    from app.services import audit_service

    await audit_service._log(ctx.db, ctx.audit_id, action, message, status, agent=agent)


async def _mark(ctx: Ctx, name: str, **fields: Any) -> None:
    audit = await ctx.audit()
    state = dict(audit.stage_state or {})
    entry = dict(state.get(name) or {})
    entry.update(fields)
    state[name] = entry
    audit.stage_state = state
    await ctx.db.commit()


def _node(ctx: Ctx, spec: StageSpec):
    async def run(state: PipelineState) -> dict[str, Any]:
        audit = await ctx.audit()
        if stage_done(audit.stage_state or {}, spec.name):
            await _log(ctx, spec.agent, "skipped", f"{spec.label}: already completed, resuming.")
            return {}
        audit.current_stage = spec.name
        audit.progress = spec.progress
        await _mark(
            ctx,
            spec.name,
            agent=spec.agent,
            label=spec.label,
            started_at=_now().isoformat(),
            completed_at=None,
            error=None,
        )
        await _log(ctx, spec.agent, "started", spec.label)
        await ctx.db.commit()  # keep the log even if the stage fails and rolls back
        try:
            await spec.run(ctx)
        except StageFailure as exc:
            await _fail(ctx, spec, exc.message)
            return {"failed": True}
        except Exception as exc:  # noqa: BLE001 - an agent must never crash the workflow
            logger.exception("[AUDIT-%s] %s failed", ctx.audit_id, spec.name)
            if spec.advisory:
                # Advisory (AI) stages degrade: the deterministic result stands on its own.
                await ctx.db.rollback()
                ctx.notes[spec.name] = f"skipped after an error ({type(exc).__name__})"
                await _mark(
                    ctx, spec.name, completed_at=_now().isoformat(), note=ctx.notes[spec.name]
                )
                await _log(ctx, spec.agent, "degraded", ctx.notes[spec.name], LogStatus.WARNING)
                return {}
            await _fail(ctx, spec, f"{spec.label} failed unexpectedly ({type(exc).__name__}).")
            return {"failed": True}
        note = ctx.notes.get(spec.name)
        await _mark(ctx, spec.name, completed_at=_now().isoformat(), note=note)
        await _log(ctx, spec.agent, "completed", note or spec.label, LogStatus.SUCCESS)
        return {}

    return run


async def _fail(ctx: Ctx, spec: StageSpec, message: str) -> None:
    from app.services import audit_service

    await audit_service._fail(ctx.db, ctx.audit_id, message)
    await _mark(ctx, spec.name, error=message)


def build_graph(ctx: Ctx):
    graph = StateGraph(PipelineState)
    for spec in STAGES:
        graph.add_node(spec.name, _node(ctx, spec))

    async def entry(state: PipelineState) -> str:
        audit = await ctx.audit()
        done = audit.stage_state or {}
        for name in STAGE_NAMES:
            if not stage_done(done, name):
                return name
        return END

    graph.add_conditional_edges(START, entry, {**{n: n for n in STAGE_NAMES}, END: END})
    for i, name in enumerate(STAGE_NAMES):
        nxt = STAGE_NAMES[i + 1] if i + 1 < len(STAGE_NAMES) else END

        def after(state: PipelineState, _nxt: str = nxt) -> str:
            return END if state.get("failed") else _nxt

        graph.add_conditional_edges(name, after, {nxt: nxt, END: END})
    return graph.compile()


async def run_pipeline(ctx: Ctx) -> None:
    audit = await ctx.audit()
    audit.status = AuditStatus.RUNNING
    audit.started_at = audit.started_at or _now()
    await ctx.db.commit()

    await build_graph(ctx).ainvoke({"failed": False})

    audit = await ctx.audit()
    if audit.status is AuditStatus.RUNNING:  # no stage failed
        audit.status = AuditStatus.COMPLETED
        audit.progress = 100
        audit.current_stage = None
        audit.completed_at = _now()
        await _log(ctx, "pipeline", "completed", "Audit completed.", LogStatus.SUCCESS)
        await ctx.db.commit()
