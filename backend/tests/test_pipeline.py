"""The source-only agent pipeline (LangGraph workflow; ADR-016, phases 6-12)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audits import get_launcher
from app.core.config import get_settings
from app.core.enums import AuditStatus, FindingStatus
from app.models import AuditLog, ReconnaissanceResult, SecurityAudit, SecurityReport, Vulnerability
from app.pipeline import stages
from app.pipeline.context import Ctx
from app.pipeline.graph import build_graph
from app.pipeline.stages import STAGE_NAMES
from app.services.audit_service import run_source_audit

pytestmark = pytest.mark.anyio

APP = (
    "import hashlib\n"
    "from flask import Flask, request\n"
    "app = Flask(__name__)\n"
    "@app.route('/s')\n"
    "def s():\n"
    "    cur.execute('SELECT * FROM t WHERE n = ' + request.args['n'])\n"
    "    return hashlib.md5(b'x').hexdigest()\n"
)


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "workspace"
    (root / "shop" / "tests").mkdir(parents=True)
    (root / "shop" / "app.py").write_text(APP, encoding="utf-8")
    (root / "shop" / "tests" / "test_app.py").write_text(
        "import hashlib\nhashlib.md5(b'fixture')\n", encoding="utf-8"
    )
    monkeypatch.setenv("SOURCE_ROOTS", str(root))
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


def _launcher_override(db_session: AsyncSession, *, run: bool):
    from app.main import app

    async def factory() -> Callable[[uuid.UUID], Awaitable[None]]:
        async def launch(audit_id: uuid.UUID) -> None:
            if run:
                await run_source_audit(db_session, audit_id)

        return launch

    app.dependency_overrides[get_launcher] = factory


@pytest.fixture
async def inline_runner(db_session: AsyncSession) -> AsyncIterator[None]:
    from app.main import app

    _launcher_override(db_session, run=True)
    yield
    app.dependency_overrides.pop(get_launcher, None)


@pytest.fixture
async def queue_only(db_session: AsyncSession) -> AsyncIterator[None]:
    from app.main import app

    _launcher_override(db_session, run=False)
    yield
    app.dependency_overrides.pop(get_launcher, None)


async def login(client: AsyncClient, email: str = "a@example.com") -> None:
    body = {"name": "Dev", "email": email, "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    res = await client.post("/api/auth/login", json={"email": email, "password": body["password"]})
    assert res.status_code == 200


async def project_audit(client: AsyncClient, workspace: Path) -> tuple[str, str]:
    created = await client.post(
        "/api/projects", json={"name": "Shop", "path": str(workspace / "shop")}
    )
    pid = created.json()["id"]
    await client.post(f"/api/projects/{pid}/authorize", json={"confirmed": True})
    res = await client.post(f"/api/projects/{pid}/audits", json={})
    assert res.status_code == 202, res.text
    return pid, res.json()["id"]


async def test_every_agent_runs_in_order_and_is_logged(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await login(client)
    _, audit_id = await project_audit(client, workspace)

    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed" and detail["progress"] == 100
    for name in STAGE_NAMES:
        entry = detail["stage_state"][name]
        assert entry["completed_at"] and entry["agent"] and entry["error"] is None

    logs = (
        await db_session.scalars(
            select(AuditLog)
            .where(AuditLog.audit_id == uuid.UUID(audit_id))
            .order_by(AuditLog.timestamp)
        )
    ).all()
    started = [e.agent for e in logs if e.action == "started"]
    assert started == [s.agent for s in stages.STAGES]  # one agent per stage, in order
    assert logs[-1].action == "completed" and logs[-1].agent == "pipeline"


async def test_reconnaissance_artifact_and_report_use_persisted_data(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await login(client)
    _, audit_id = await project_audit(client, workspace)
    recon = await db_session.scalar(
        select(ReconnaissanceResult).where(ReconnaissanceResult.audit_id == uuid.UUID(audit_id))
    )
    assert recon is not None and "GET /s" in recon.endpoints
    assert "query:n" in recon.raw_result["model"]["parameters"]
    assert any(r["path"] == "/s" for r in recon.raw_result["routes"])

    report = await db_session.scalar(
        select(SecurityReport).where(SecurityReport.audit_id == uuid.UUID(audit_id))
    )
    assert report is not None
    assert "Authorization matrix" in report.report_html
    assert "Source reconnaissance" in report.report_html  # timeline entry from the pipeline
    assert "Rule-based validation" in report.report_html


async def test_safe_validation_attaches_verified_fix_evidence(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await login(client)
    _, audit_id = await project_audit(client, workspace)
    rows = (
        await db_session.scalars(
            select(Vulnerability).where(Vulnerability.audit_id == uuid.UUID(audit_id))
        )
    ).all()
    weak = [r for r in rows if r.type == "weak_hash" and r.endpoint.startswith("app.py")]
    assert weak
    fix = weak[0].validation_result["fix_verification"]
    assert fix["verified"] is True and "sha256" in fix["diff"] and fix["check"]
    # a finding with no deterministic fix carries no fix evidence
    sqli = next(r for r in rows if r.type == "sql_injection")
    assert "fix_verification" not in (sqli.validation_result or {})


async def test_validator_agent_reclassifies_test_code(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await login(client)
    _, audit_id = await project_audit(client, workspace)
    rows = (
        await db_session.scalars(
            select(Vulnerability).where(Vulnerability.audit_id == uuid.UUID(audit_id))
        )
    ).all()
    in_tests = [r for r in rows if r.endpoint.startswith("tests/")]
    assert in_tests and all(r.status is FindingStatus.INFORMATIONAL for r in in_tests)
    assert all(r.status is not FindingStatus.CONFIRMED for r in rows)
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert any("reclassified" in n for n in detail["validation_notes"])


async def test_authorization_revoked_before_the_run_blocks_it(
    client: AsyncClient, workspace: Path, queue_only: None, db_session: AsyncSession
) -> None:
    await login(client)
    pid, audit_id = await project_audit(client, workspace)  # queued, not run
    assert (await client.post(f"/api/projects/{pid}/revoke")).status_code == 200

    await run_source_audit(db_session, uuid.UUID(audit_id))
    audit = await db_session.get(SecurityAudit, uuid.UUID(audit_id))
    await db_session.refresh(audit)
    assert audit.status is AuditStatus.FAILED
    assert "revoked" in (audit.error_message or "")
    assert audit.stage_state["authorization"]["error"]
    # no later agent ran, nothing was read or stored
    assert "reconnaissance" not in audit.stage_state
    assert (await db_session.scalars(select(Vulnerability))).all() == []


async def test_resume_continues_from_the_failed_stage(
    client: AsyncClient,
    workspace: Path,
    inline_runner: None,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await login(client)
    calls = {"scan": 0}
    real_scan = stages.scan_repo

    def counting_scan(*a, **kw):
        calls["scan"] += 1
        return real_scan(*a, **kw)

    monkeypatch.setattr(stages, "scan_repo", counting_scan)

    async def boom(ctx: Ctx) -> None:
        raise RuntimeError("transient")

    real_validator = stages.validator
    specs = [
        s if s.name != "validator" else stages.StageSpec(s.name, s.agent, s.label, s.progress, boom)
        for s in stages.STAGES
    ]
    monkeypatch.setattr("app.pipeline.graph.STAGES", specs)

    _, audit_id = await project_audit(client, workspace)
    failed = (await client.get(f"/api/audits/{audit_id}")).json()
    assert failed["status"] == "failed"
    assert failed["stage_state"]["validator"]["error"]
    assert failed["stage_state"]["scanner"]["completed_at"]  # earlier work is kept
    assert calls["scan"] == 1

    # fix the cause and resume: scanner must not run again, the audit completes
    healthy = [
        s
        if s.name != "validator"
        else stages.StageSpec(s.name, s.agent, s.label, s.progress, real_validator)
        for s in specs
    ]
    monkeypatch.setattr("app.pipeline.graph.STAGES", healthy)
    res = await client.post(f"/api/audits/{audit_id}/retry?resume=true")
    assert res.status_code == 202, res.text
    done = (await client.get(f"/api/audits/{audit_id}")).json()
    assert done["status"] == "completed"
    assert calls["scan"] == 1  # resumed, not restarted
    logs = (await client.get(f"/api/audits/{audit_id}/logs")).json()
    scanner_starts = [
        e for e in logs if e["action"] == "started" and e["agent"] == "vulnerability-scanner-agent"
    ]
    assert len(scanner_starts) == 1  # the resumed run went straight to the failed stage
    validator_starts = [
        e for e in logs if e["action"] == "started" and e["agent"] == "validator-agent"
    ]
    assert len(validator_starts) == 2  # once failed, once resumed

    # a clean retry afterwards would re-scan
    assert (await client.post(f"/api/audits/{audit_id}/retry")).status_code == 409  # completed


async def test_the_workflow_is_a_langgraph_graph(db_session: AsyncSession) -> None:
    graph = build_graph(Ctx(db=db_session, audit_id=uuid.uuid4()))
    names = set(graph.get_graph().nodes)
    assert set(STAGE_NAMES) <= names
    assert hasattr(graph, "ainvoke")
