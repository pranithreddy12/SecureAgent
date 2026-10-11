"""Persisted source audits (ADR-011): gate, confinement, runner, ownership, report."""

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
from app.models import SecurityAudit, Vulnerability
from app.pipeline.stages import STAGE_NAMES
from app.services.audit_service import run_source_audit

pytestmark = pytest.mark.anyio

VULN_APP = (
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
    (root / "shop").mkdir(parents=True)
    (root / "shop" / "app.py").write_text(VULN_APP, encoding="utf-8")
    monkeypatch.setenv("SOURCE_ROOTS", str(root))
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


@pytest.fixture
async def inline_runner(db_session: AsyncSession) -> AsyncIterator[None]:
    """Run each audit to completion inside the request, on the test session."""
    from app.main import app

    async def launcher_factory() -> Callable[[uuid.UUID], Awaitable[None]]:
        async def launch(audit_id: uuid.UUID) -> None:
            await run_source_audit(db_session, audit_id)

        return launch

    app.dependency_overrides[get_launcher] = launcher_factory
    yield
    app.dependency_overrides.pop(get_launcher, None)


async def register_login(client: AsyncClient, email: str) -> None:
    body = {"name": "Dev", "email": email, "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    res = await client.post("/api/auth/login", json={"email": email, "password": body["password"]})
    assert res.status_code == 200


def create_body(path: Path, **kw) -> dict:
    return {"path": str(path), "authorization_confirmed": True, **kw}


async def test_requires_authentication(client: AsyncClient) -> None:
    res = await client.post(
        "/api/audits/source", json={"path": "/x", "authorization_confirmed": True}
    )
    assert res.status_code == 401
    assert (await client.get("/api/audits")).status_code == 401


async def test_authorization_must_be_confirmed(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await register_login(client, "a@example.com")
    res = await client.post(
        "/api/audits/source",
        json={"path": str(workspace / "shop"), "authorization_confirmed": False},
    )
    assert res.status_code == 400
    assert "authorized" in res.json()["detail"]


async def test_disabled_without_source_roots(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SOURCE_ROOTS", "")
    get_settings.cache_clear()
    await register_login(client, "a@example.com")
    res = await client.post("/api/audits/source", json=create_body(tmp_path))
    assert res.status_code == 503
    get_settings.cache_clear()


async def test_path_outside_roots_and_non_directories_rejected(
    client: AsyncClient, workspace: Path, inline_runner: None, tmp_path: Path
) -> None:
    await register_login(client, "a@example.com")
    outside = tmp_path / "secrets"
    outside.mkdir()
    for bad in (outside, workspace / ".." / "secrets", workspace / "shop" / "app.py"):
        res = await client.post("/api/audits/source", json=create_body(bad))
        assert res.status_code == 400, bad
    assert "outside" not in (await client.get("/api/audits")).text  # nothing was created
    assert (await client.get("/api/audits")).json() == []


async def test_full_audit_lifecycle(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await register_login(client, "a@example.com")
    res = await client.post(
        "/api/audits/source", json=create_body(workspace / "shop", label="Shop")
    )
    assert res.status_code == 202, res.text
    audit_id = res.json()["id"]

    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed"
    assert detail["progress"] == 100
    assert detail["audit_type"] == "source"
    assert detail["source_label"] == "Shop"
    assert detail["total_findings"] >= 2
    assert set(detail["stage_state"]) >= set(STAGE_NAMES)
    stages = {k: detail["stage_state"][k] for k in STAGE_NAMES}
    assert all(s["completed_at"] for s in stages.values())
    assert detail["attack_chains"], "the vulnerable route should produce an attack chain"
    assert detail["attack_chains"][0]["fix_first"]
    assert "Flask" in detail["application_model"]["technologies"]
    assert "query:n" in detail["application_model"]["parameters"]

    findings = (await client.get(f"/api/audits/{audit_id}/findings")).json()
    types = {f["type"] for f in findings}
    assert {"sql_injection", "weak_hash"} <= types
    assert all(f["status"] != "confirmed" for f in findings)  # static analysis never confirms

    logs = (await client.get(f"/api/audits/{audit_id}/logs")).json()
    assert [entry["action"] for entry in logs][0] == "queued"
    assert logs[-1]["action"] == "completed"

    report = await client.get(f"/api/audits/{audit_id}/report")
    assert report.status_code == 200
    assert "default-src 'none'" in report.headers["content-security-policy"]
    assert "SQL injection" in report.text or "sql" in report.text.lower()
    assert "a@example.com" in report.text  # authorizing user is recorded
    download = await client.get(f"/api/audits/{audit_id}/report?download=true")
    assert "attachment" in download.headers["content-disposition"]

    listing = (await client.get("/api/audits")).json()
    assert [a["id"] for a in listing] == [audit_id]

    rows = (await db_session.scalars(select(Vulnerability))).all()
    assert len({v.fingerprint for v in rows}) == len(rows)


async def test_other_users_cannot_see_an_audit(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await register_login(client, "a@example.com")
    audit_id = (
        await client.post("/api/audits/source", json=create_body(workspace / "shop"))
    ).json()["id"]
    client.cookies.clear()
    await register_login(client, "b@example.com")
    for suffix in ("", "/findings", "/logs", "/report"):
        res = await client.get(f"/api/audits/{audit_id}{suffix}")
        assert res.status_code == 404, suffix
    assert (await client.get("/api/audits")).json() == []


async def test_failure_marks_audit_failed_without_leaking_paths(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await register_login(client, "a@example.com")
    (workspace / "shop" / "secureagent-intent.json").write_text("not json", encoding="utf-8")
    res = await client.post("/api/audits/source", json=create_body(workspace / "shop"))
    audit_id = res.json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "failed"
    assert detail["error_message"]
    assert str(workspace) not in detail["error_message"]
    logs = (await client.get(f"/api/audits/{audit_id}/logs")).json()
    assert logs[-1]["status"] == "error"
    audit = await db_session.get(SecurityAudit, uuid.UUID(audit_id))
    assert audit is not None and audit.completed_at is not None


async def test_exclude_patterns_are_applied(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await register_login(client, "a@example.com")
    res = await client.post(
        "/api/audits/source", json=create_body(workspace / "shop", exclude=["app.py"])
    )
    detail = (await client.get(f"/api/audits/{res.json()['id']}")).json()
    assert detail["status"] == "completed"
    assert detail["total_findings"] == 0


async def test_unknown_audit_id_is_404(client: AsyncClient) -> None:
    await register_login(client, "a@example.com")
    res = await client.get(f"/api/audits/{uuid.uuid4()}")
    assert res.status_code == 404


async def test_retry_reruns_a_failed_audit_with_a_clean_slate(
    client: AsyncClient, workspace: Path, inline_runner: None, db_session: AsyncSession
) -> None:
    await register_login(client, "a@example.com")
    spec = workspace / "shop" / "secureagent-intent.json"
    spec.write_text("not json", encoding="utf-8")
    created = await client.post("/api/audits/source", json=create_body(workspace / "shop"))
    audit_id = created.json()["id"]
    assert (await client.get(f"/api/audits/{audit_id}")).json()["status"] == "failed"

    # A completed audit cannot be retried; fix the cause and retry the failed one.
    spec.unlink()
    res = await client.post(f"/api/audits/{audit_id}/retry")
    assert res.status_code == 202, res.text
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed" and detail["error_message"] is None
    assert detail["total_findings"] >= 2
    logs = [e["action"] for e in (await client.get(f"/api/audits/{audit_id}/logs")).json()]
    assert "failed" in logs and "retry" in logs and logs[-1] == "completed"

    rows = (await db_session.scalars(select(Vulnerability))).all()
    assert len(rows) == detail["total_findings"]  # no duplicates from the first attempt

    again = await client.post(f"/api/audits/{audit_id}/retry")
    assert again.status_code == 409


async def test_retry_is_owner_only(
    client: AsyncClient, workspace: Path, inline_runner: None
) -> None:
    await register_login(client, "a@example.com")
    (workspace / "shop" / "secureagent-intent.json").write_text("x", encoding="utf-8")
    audit_id = (
        await client.post("/api/audits/source", json=create_body(workspace / "shop"))
    ).json()["id"]
    client.cookies.clear()
    await register_login(client, "b@example.com")
    assert (await client.post(f"/api/audits/{audit_id}/retry")).status_code == 404
