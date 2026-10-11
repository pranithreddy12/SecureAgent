"""Opt-in AI stages in the audit pipeline: consent, graceful degradation, no authority (ADR-018)."""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis import llm_review as lr
from app.api.audits import get_launcher
from app.core.config import get_settings
from app.core.enums import FindingStatus
from app.models import SecurityReport, Vulnerability
from app.pipeline import stages
from app.pipeline.context import Ctx
from app.services.audit_service import run_source_audit

pytestmark = pytest.mark.anyio

SECRET = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"
APP = f"""\
import sqlite3
from flask import Flask, request
app = Flask(__name__)
db = sqlite3.connect("shop.db")
API_SECRET = "{SECRET}"


@app.route("/search")
def search():
    term = request.args.get("q")
    cur = db.cursor()
    cur.execute("SELECT * FROM t WHERE n = '" + term + "'")
    return str(cur.fetchall())
"""  # noqa: S608 - fixture source text, not a query


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "workspace"
    (root / "shop").mkdir(parents=True)
    (root / "shop" / "app.py").write_text(APP, encoding="utf-8")
    monkeypatch.setenv("SOURCE_ROOTS", str(root))
    monkeypatch.setenv("LLM_API_KEY", "")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "cache"))  # isolate the review cache
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


@pytest.fixture
async def inline_runner(db_session: AsyncSession) -> AsyncIterator[None]:
    from app.main import app

    async def factory() -> Callable[[uuid.UUID], Awaitable[None]]:
        async def launch(audit_id: uuid.UUID) -> None:
            await run_source_audit(db_session, audit_id)

        return launch

    app.dependency_overrides[get_launcher] = factory
    yield
    app.dependency_overrides.pop(get_launcher, None)


class FakeLLM:
    """Stands in for the Anthropic API and records every payload that would leave the server."""

    def __init__(
        self, verdict="false_positive", narrative="The shop service has one injection risk."
    ):
        self.verdict, self.narrative = verdict, narrative
        self.payloads: list[dict] = []

    def __call__(self, payload: dict, headers: dict) -> dict:
        self.payloads.append(payload)
        prompt = payload["messages"][0]["content"]
        if payload["system"] == lr.NARRATIVE_SYSTEM:
            return {"content": [{"type": "text", "text": self.narrative}]}
        quote = ""
        for line in prompt.splitlines():
            m = re.match(r"\s*\d+\s{2}(.*execute\(.*)", line)
            if m:
                quote = m.group(1).strip()
        body = {
            "verdict": self.verdict,
            "confidence": 0.9,
            "reason": "Bound upstream.",
            "quote": quote,
        }
        return {"content": [{"type": "text", "text": json.dumps(body)}]}


async def login(client: AsyncClient, email: str = "a@example.com") -> None:
    body = {"name": "Dev", "email": email, "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    res = await client.post("/api/auth/login", json={"email": email, "password": body["password"]})
    assert res.status_code == 200


async def start(client: AsyncClient, workspace: Path, **extra):
    return await client.post(
        "/api/audits/source",
        json={
            "path": str(workspace / "shop"),
            "authorization_confirmed": True,
            **extra,
        },
    )


def enable_ai(monkeypatch: pytest.MonkeyPatch, llm: FakeLLM) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-test-key")
    get_settings.cache_clear()
    monkeypatch.setattr(lr, "http_transport", llm)


async def test_ai_stages_are_skipped_unless_requested(
    client: AsyncClient, workspace: Path, inline_runner: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    llm = FakeLLM()
    enable_ai(monkeypatch, llm)  # a key exists on the server, but the audit did not opt in
    await login(client)
    audit_id = (await start(client, workspace)).json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed" and detail["ai"]["enabled"] is False
    assert llm.payloads == []  # nothing left the server
    assert "skipped" in detail["stage_state"]["ai_validator"]["note"]
    findings = (await client.get(f"/api/audits/{audit_id}/findings")).json()
    assert all(f["ai_review"] is None for f in findings)


async def test_requesting_ai_without_a_server_key_is_refused(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await login(client)
    res = await start(client, workspace, ai_review=True)
    assert res.status_code == 400 and "not configured" in res.json()["detail"]
    assert (await client.get("/api/audits")).json() == []


async def test_ai_review_and_narrative_are_stored_but_have_no_authority(
    client: AsyncClient,
    workspace: Path,
    inline_runner: None,
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
) -> None:
    llm = FakeLLM(verdict="false_positive")
    enable_ai(monkeypatch, llm)
    await login(client)
    audit_id = (await start(client, workspace, ai_review=True)).json()["id"]

    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed"
    assert detail["ai"]["enabled"] and detail["ai"]["reviewed"] >= 1
    assert detail["ai"]["summary_written"] is True

    findings = (await client.get(f"/api/audits/{audit_id}/findings")).json()
    sqli = next(f for f in findings if f["type"] == "sql_injection")
    assert sqli["ai_review"]["verdict"] == "false_positive"
    assert sqli["ai_review"]["quote_verified"] is True
    # a "false positive" verdict from the model does NOT change the deterministic status
    assert sqli["status"] != "false_positive"
    rows = (await db_session.scalars(select(Vulnerability))).all()
    assert all(r.status is not FindingStatus.FALSE_POSITIVE for r in rows)

    report = await db_session.scalar(
        select(SecurityReport).where(SecurityReport.audit_id == uuid.UUID(audit_id))
    )
    assert "The shop service has one injection risk." in report.report_html
    assert "Written by AI" in report.report_html and "authoritative" in report.report_html
    assert "AI review" in report.report_html


async def test_nothing_secret_and_no_code_in_the_summary_payload(
    client: AsyncClient, workspace: Path, inline_runner: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    llm = FakeLLM()
    enable_ai(monkeypatch, llm)
    await login(client)
    await start(client, workspace, ai_review=True)
    assert llm.payloads
    everything = json.dumps(llm.payloads)
    assert SECRET not in everything
    narrative = next(p for p in llm.payloads if p["system"] == lr.NARRATIVE_SYSTEM)
    sent = narrative["messages"][0]["content"]
    # facts only: titles/counts/locations, no source lines
    assert "SELECT * FROM t" not in sent and "request.args" not in sent
    assert "db.cursor" not in sent and "return str" not in sent
    assert "sql_injection" in sent


async def test_an_unusable_or_overclaiming_narrative_falls_back(
    client: AsyncClient, workspace: Path, inline_runner: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    enable_ai(
        monkeypatch, FakeLLM(narrative="The injection was confirmed exploited in production.")
    )
    await login(client)
    audit_id = (await start(client, workspace, ai_review=True)).json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed"
    assert detail["ai"]["summary_written"] is False
    assert any("unusable" in p for p in detail["ai"]["problems"])


async def test_api_failure_degrades_without_failing_the_audit(
    client: AsyncClient, workspace: Path, inline_runner: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def down(payload, headers):
        raise lr.ReviewError("could not reach the API: URLError")

    enable_ai(monkeypatch, FakeLLM())
    monkeypatch.setattr(lr, "http_transport", down)
    await login(client)
    audit_id = (await start(client, workspace, ai_review=True)).json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed"  # the deterministic result stands
    assert detail["total_findings"] >= 1
    assert detail["ai"]["reviewed"] == 0
    assert any("could not reach" in p for p in detail["ai"]["problems"])


async def test_an_unexpected_ai_stage_error_degrades_instead_of_failing(
    client: AsyncClient, workspace: Path, inline_runner: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    enable_ai(monkeypatch, FakeLLM())

    async def boom(ctx: Ctx) -> None:
        raise RuntimeError("bug in an advisory stage")

    specs = [
        stages.StageSpec(s.name, s.agent, s.label, s.progress, boom, True)
        if s.name == "ai_validator"
        else s
        for s in stages.STAGES
    ]
    monkeypatch.setattr("app.pipeline.graph.STAGES", specs)
    await login(client)
    audit_id = (await start(client, workspace, ai_review=True)).json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed"
    logs = (await client.get(f"/api/audits/{audit_id}/logs")).json()
    assert any(e["action"] == "degraded" and e["agent"] == "ai-validator-agent" for e in logs)
