"""The pipeline's agents (source-only; ADR-016).

Each agent is a coroutine over a :class:`Ctx`. They are *deterministic*: no network access, no
execution of scanned code, no LLM. Persisted artifacts are the contract between agents, so any
stage can be re-run (idempotent) and a failed audit can resume.

stage             agent (phase)               writes
authorization     authorization gate (5)      enforces authorization and scope
reconnaissance    reconnaissance agent (7)    reconnaissance_results
scanner           vulnerability scanner (8)   vulnerabilities (raw findings)
safe_validation   safe-validation agent (11)  vulnerabilities.validation_result
validator         validator agent (12)        status / confidence of findings
correlation       correlation agent (6)       stage_state.attack_chains
report            report agent (13)           security_reports

ZAP and Nuclei (phases 9-10) are dynamic scanners with no source-file semantics; they are
intentionally absent from this pipeline.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import delete

from app.analysis import llm_review as lr
from app.analysis.baseline import fingerprint
from app.analysis.chains import find_chains
from app.analysis.dependencies import is_lockfile, parse_dependencies
from app.analysis.fixes import propose_fixes
from app.analysis.ingest import (
    IngestError,
    IngestStats,
    iter_source_files,
    load_ignore_file,
    read_text,
)
from app.analysis.intent import IntentError
from app.analysis.recon import ApplicationModel
from app.analysis.reporting import scan_to_report_context
from app.analysis.routes import Route, extract_routes
from app.analysis.scanner import scan_repo
from app.analysis.validation import rule_for, validate_findings
from app.core.config import get_settings
from app.core.enums import FindingStatus
from app.core.paths import PathNotAllowed, confine_to_roots
from app.models import ReconnaissanceResult, SecurityReport, SourceProject, Vulnerability
from app.pipeline.context import Ctx, StageFailure, to_report_finding
from app.pipeline.report_builder import build_context
from app.reports.renderer import render_html


@dataclass(frozen=True)
class StageSpec:
    name: str
    agent: str
    label: str
    progress: int
    run: Callable[[Ctx], Awaitable[None]]
    advisory: bool = False  # AI stages: failure degrades instead of failing the audit


def _root(audit) -> str:
    if not audit.source_path:
        raise StageFailure("The audit has no source directory.")
    return audit.source_path


def _exclude(audit) -> list[str]:
    return list((audit.stage_state or {}).get("exclude", []))


# --------------------------------------------------------------------------- phase 5


async def authorization_gate(ctx: Ctx) -> None:
    audit = await ctx.audit()
    if not audit.authorization_statement or audit.authorized_at is None:
        raise StageFailure("The audit has no recorded authorization.")
    roots = get_settings().source_roots
    if not roots:
        raise StageFailure("Source audits are disabled on this server.")
    try:
        resolved = confine_to_roots(_root(audit), roots)
    except PathNotAllowed:
        raise StageFailure("The source directory is outside the allowed roots.") from None
    if not resolved.is_dir():
        raise StageFailure("The source directory could not be read.")
    if audit.source_project_id is not None:
        project = await ctx.db.get(SourceProject, audit.source_project_id)
        if project is None or not project.authorization_confirmed:
            raise StageFailure("Authorization for this project was revoked before the audit ran.")


# --------------------------------------------------------------------------- phase 7


def _recon_sync(root: str, exclude: list[str]):
    model = ApplicationModel()
    routes: list[Route] = []
    deps = []
    stats = IngestStats()
    for f in iter_source_files(root, stats=stats, exclude=[*load_ignore_file(root), *exclude]):
        try:
            text = read_text(f)
        except OSError:
            continue
        model.absorb_file(f.relpath, text)
        routes.extend(extract_routes(f.relpath, text))
        if is_lockfile(f.relpath):
            deps.extend(parse_dependencies(f.relpath, text))
    for r in routes:
        model.absorb_route_path(r.path)
    for d in deps:
        model.absorb_dependency(d.name)
    return model, routes, deps, stats


async def reconnaissance(ctx: Ctx) -> None:
    audit = await ctx.audit()
    try:
        model, routes, deps, stats = await asyncio.to_thread(
            _recon_sync, _root(audit), _exclude(audit)
        )
    except (IngestError, OSError):
        raise StageFailure("The source directory could not be read.") from None
    await ctx.db.execute(
        delete(ReconnaissanceResult).where(ReconnaissanceResult.audit_id == ctx.audit_id)
    )
    summary = model.summary()
    ctx.db.add(
        ReconnaissanceResult(
            audit_id=ctx.audit_id,
            technologies=sorted({d.ecosystem for d in deps} | model.technologies),
            endpoints=sorted({f"{r.method} {r.path}" for r in routes}),
            api_endpoints=sorted(
                {f"{r.method} {r.path}" for r in routes if r.path.startswith("/api")}
            ),
            forms=[],
            headers={},
            raw_result={
                "routes": [r.__dict__ for r in routes],
                "model": summary,
                "files_scanned": stats.files_scanned,
                "dependencies": len(deps),
            },
        )
    )
    await ctx.db.flush()


# --------------------------------------------------------------------------- phase 8


async def vulnerability_scanner(ctx: Ctx) -> None:
    audit = await ctx.audit()
    try:
        result = await asyncio.to_thread(
            scan_repo, _root(audit), check_osv=False, exclude=_exclude(audit)
        )
    except IntentError:
        raise StageFailure("The intent spec (secureagent-intent.json) is invalid.") from None
    except (IngestError, OSError):
        raise StageFailure("The source directory could not be read.") from None
    # Validation is a separate agent; the scanner persists raw findings.
    report = scan_to_report_context(result, repo_label=audit.source_label, validate=False)
    await ctx.db.execute(delete(Vulnerability).where(Vulnerability.audit_id == ctx.audit_id))
    seen: dict[str, int] = {}
    for f in report.findings:
        fp = fingerprint(f)
        seen[fp] = seen.get(fp, 0) + 1
        unique = fp if seen[fp] == 1 else f"{fp}-{seen[fp]}"  # same kind/file/title, other line
        ctx.db.add(
            Vulnerability(
                audit_id=ctx.audit_id,
                fingerprint=unique,
                title=f.title[:255],
                type=f.type[:80],
                endpoint=f.endpoint[:2048],
                parameter=(f.parameter or None) and f.parameter[:255],
                severity=f.severity,
                confidence=f.confidence,
                status=f.status,
                status_reason=f.status_reason,
                sources=list(f.sources),
                description=f.description,
                impact=f.impact,
                evidence=f.evidence,
                validation_result={"method": f.validation_method},
                owasp_category=f.owasp_category,
                cwe=f.cwe,
                cve=f.cve,
                cvss=f.cvss.model_dump() if f.cvss else None,
                remediation=f.remediation,
            )
        )
    await ctx.db.flush()
    ctx.notes["scan"] = f"{result.stats.files_scanned} files, {len(report.findings)} findings"


# --------------------------------------------------------------------------- phase 11


async def safe_validation(ctx: Ctx) -> None:
    """Source form of safe validation: prove a deterministic fix removes the finding.

    Never executes the project. A patch is *verified* only when the patched file parses and a
    re-scan shows the finding gone with nothing new (ADR-013).
    """
    audit = await ctx.audit()
    rows = await ctx.finding_rows()
    findings = [to_report_finding(r) for r in rows]
    patches = await asyncio.to_thread(propose_fixes, _root(audit), findings)
    index = {}
    for p in patches:
        for change in p.changes:
            index[(p.path, change.line, change.finding_type)] = (p, change)
    verified = 0
    for row in rows:
        file, _, line = row.endpoint.rpartition(":")
        hit = index.get((file, int(line) if line.isdigit() else -1, row.type))
        if hit is None:
            continue
        patch, change = hit
        verified += 1 if patch.verified else 0
        row.validation_result = {
            **(row.validation_result or {}),
            "fix_verification": {
                "verified": patch.verified,
                "note": patch.note,
                "what": change.description,
                "check": change.caveat,
                "diff": patch.diff[:20000],
            },
        }
    await ctx.db.flush()
    ctx.notes["safe_validation"] = f"{len(patches)} patch(es), {verified} finding fix(es) verified"


# --------------------------------------------------------------------------- phase 12


async def validator(ctx: Ctx) -> None:
    rows = await ctx.finding_rows()
    reported = [to_report_finding(r) for r in rows]
    updated, applied = validate_findings(reported)
    for row, before, after in zip(rows, reported, updated, strict=True):
        if after.status is FindingStatus.INFORMATIONAL and before.status is not after.status:
            row.status = after.status
            row.confidence = after.confidence
            row.status_reason = after.status_reason
            row.validation_result = {
                **(row.validation_result or {}),
                "rule": rule_for(before),
                "method": after.validation_method,
            }
    audit = await ctx.audit()
    state = dict(audit.stage_state or {})
    state["validation_notes"] = [
        f"{n} finding(s) reclassified as informational by rule '{rule}' "
        "(see each finding's reason)."
        for rule, n in sorted(applied.items())
    ]
    audit.stage_state = state
    await ctx.db.flush()
    ctx.notes["validator"] = f"{sum(applied.values())} reclassified"


# --------------------------------------------------------------------------- AI (opt-in)
#
# The two AI stages are *advisory*: they never change a finding's status, severity or the gate, and
# a failure (no key, network down, unusable answer) is recorded and skipped -- it never fails the
# audit. They run only when the audit was created with explicit consent (stage_state["ai"]).


def _severity_rank(row) -> tuple[int, float]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    return order.get(row.severity.value, 9), -row.confidence


async def _ai_settings(ctx: Ctx):
    audit = await ctx.audit()
    ai = (audit.stage_state or {}).get("ai") or {}
    if not ai.get("consent"):
        return audit, None, "skipped: AI review was not requested for this audit"
    settings = get_settings()
    if not settings.llm_api_key:
        return audit, None, "skipped: no LLM key is configured on this server"
    reviewer = lr.Reviewer(
        api_key=settings.llm_api_key,
        model=settings.llm_model or lr.DEFAULT_MODEL,
        transport=lr.http_transport,  # looked up now so tests can replace it
        cache_path=lr.default_cache_path(),
    )
    return audit, (reviewer, ai), None


async def _record_ai(ctx: Ctx, audit, **fields) -> None:
    state = dict(audit.stage_state or {})
    ai = dict(state.get("ai") or {})
    ai.update(fields)
    state["ai"] = ai
    audit.stage_state = state
    await ctx.db.flush()


async def ai_validator(ctx: Ctx) -> None:
    """Second opinion on the most severe findings (ADR-018). Stored beside the finding only."""
    audit, configured, why = await _ai_settings(ctx)
    if configured is None:
        ctx.notes["ai_validator"] = why
        return
    reviewer, ai = configured
    limit = int(ai.get("limit", 15))
    rows = [
        r
        for r in await ctx.finding_rows()
        if r.type in lr.REVIEWABLE
        and r.status not in (FindingStatus.INFORMATIONAL, FindingStatus.FALSE_POSITIVE)
    ]
    rows.sort(key=_severity_rank)
    reviewed = 0
    problem = None
    for row in rows[:limit]:
        finding = to_report_finding(row)
        path = lr.evidence_path(finding.evidence)
        context = lr.build_context(_root(audit), finding, path)
        if context is None:
            continue
        try:
            review = await asyncio.to_thread(reviewer.review, finding, context, path)
        except lr.ReviewError as exc:
            problem = str(exc)
            break
        row.validation_result = {**(row.validation_result or {}), "ai_review": asdict(review)}
        reviewed += 1
    await asyncio.to_thread(reviewer.save_cache)
    await _record_ai(ctx, audit, model=reviewer.model, reviewed=reviewed, validator_problem=problem)
    ctx.notes["ai_validator"] = f"reviewed {reviewed} finding(s)" + (
        f"; stopped: {problem}" if problem else ""
    )


async def ai_narrative(ctx: Ctx) -> None:
    """Executive summary from a code-free fact sheet (titles, counts, locations)."""
    audit, configured, why = await _ai_settings(ctx)
    if configured is None:
        ctx.notes["ai_narrative"] = why
        return
    reviewer, _ai = configured
    recon = await _recon(ctx)
    context = await build_context(ctx.db, audit, recon, await ctx.finding_rows())
    facts = lr.narrative_facts(context)
    try:
        text = await asyncio.to_thread(lr.narrate, reviewer, facts)
    except lr.ReviewError as exc:
        await _record_ai(ctx, audit, summary_problem=str(exc))
        ctx.notes["ai_narrative"] = f"unavailable: {exc}; the deterministic summary is used"
        return
    if not text:
        await _record_ai(ctx, audit, summary_problem="the answer was unusable")
        ctx.notes["ai_narrative"] = "unusable answer; the deterministic summary is used"
        return
    await _record_ai(
        ctx,
        audit,
        narrative={
            "text": text,
            "model": reviewer.model,
            "generated_at": datetime.now(UTC).isoformat(),
        },
    )
    ctx.notes["ai_narrative"] = "summary written from the structured findings"


# --------------------------------------------------------------------------- correlation


async def correlation(ctx: Ctx) -> None:
    recon = await _recon(ctx)
    routes = [Route(**r) for r in (recon.raw_result or {}).get("routes", [])]
    findings = [to_report_finding(r) for r in await ctx.finding_rows()]
    chains = find_chains(findings, routes)
    audit = await ctx.audit()
    state = dict(audit.stage_state or {})
    state["attack_chains"] = [c.model_dump(mode="json") for c in chains]
    state["application_model"] = (recon.raw_result or {}).get("model", {})
    audit.stage_state = state
    await ctx.db.flush()
    ctx.notes["correlation"] = f"{len(chains)} chain(s)"


async def _recon(ctx: Ctx) -> ReconnaissanceResult:
    from sqlalchemy import select

    recon = await ctx.db.scalar(
        select(ReconnaissanceResult).where(ReconnaissanceResult.audit_id == ctx.audit_id)
    )
    if recon is None:
        raise StageFailure("Reconnaissance results are missing; run the audit again.")
    return recon


# --------------------------------------------------------------------------- report


async def report(ctx: Ctx) -> None:
    audit = await ctx.audit()
    recon = await _recon(ctx)
    rows = await ctx.finding_rows()
    context = await build_context(ctx.db, audit, recon, rows)
    html = await asyncio.to_thread(render_html, context)
    await ctx.db.execute(delete(SecurityReport).where(SecurityReport.audit_id == ctx.audit_id))
    ctx.db.add(
        SecurityReport(
            audit_id=ctx.audit_id,
            summary=f"{len(context.findings)} findings; {context.risk_rating} overall risk.",
            report_html=html,
        )
    )
    await ctx.db.flush()


STAGES: list[StageSpec] = [
    StageSpec(
        "authorization",
        "authorization-gate",
        "Check authorization and scope",
        5,
        authorization_gate,
    ),
    StageSpec("reconnaissance", "reconnaissance-agent", "Map the application", 20, reconnaissance),
    StageSpec(
        "scanner", "vulnerability-scanner-agent", "Analyse source", 50, vulnerability_scanner
    ),
    StageSpec("safe_validation", "safe-validation-agent", "Verify fixes", 65, safe_validation),
    StageSpec("validator", "validator-agent", "Reduce false positives", 72, validator),
    StageSpec(
        "ai_validator",
        "ai-validator-agent",
        "AI review of findings (opt-in)",
        80,
        ai_validator,
        True,
    ),
    StageSpec("correlation", "correlation-agent", "Correlate attack chains", 86, correlation),
    StageSpec(
        "ai_narrative", "ai-report-narrative-agent", "AI summary (opt-in)", 91, ai_narrative, True
    ),
    StageSpec("report", "report-agent", "Generate report", 95, report),
]
STAGE_NAMES = [s.name for s in STAGES]
