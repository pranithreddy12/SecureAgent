"""Live targets and the live-agent pipeline (ADR-044): auth, safety gating, a real end-to-end run
against a local HTTP server (no ZAP/Nuclei required -- they degrade gracefully when unavailable,
exactly as they would in any environment without those binaries configured)."""

from __future__ import annotations

import threading
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.audits import get_launcher
from app.core.config import get_settings
from app.services.live_audit_service import run_live_audit

pytestmark = pytest.mark.anyio


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:  # quiet the test output
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        body = b"<html><body><h1>Test target</h1><a href='/about'>About</a></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_target_url() -> str:
    """A real HTTP server on loopback, deliberately missing security headers (CSP, HSTS, ...) so
    the passive scanner has something genuine to find -- no fixture faking, a real response."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()
    thread.join(timeout=2)


@pytest.fixture
def allow_private(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def inline_runner(db_session: AsyncSession) -> AsyncIterator[None]:
    """Run each live audit to completion inside the request, on the test session."""
    from app.main import app

    async def factory() -> Callable[[uuid.UUID], Awaitable[None]]:
        async def launch(audit_id: uuid.UUID) -> None:
            await run_live_audit(db_session, audit_id)

        return launch

    app.dependency_overrides[get_launcher] = factory
    yield
    app.dependency_overrides.pop(get_launcher, None)


async def register_login(client: AsyncClient, email: str) -> None:
    body = {"name": "Dev", "email": email, "password": "correct-horse-battery"}
    assert (await client.post("/api/auth/register", json=body)).status_code == 201
    res = await client.post("/api/auth/login", json={"email": email, "password": body["password"]})
    assert res.status_code == 200


async def test_requires_authentication(client: AsyncClient) -> None:
    assert (await client.get("/api/targets")).status_code == 401
    res = await client.post("/api/targets", json={"name": "x", "url": "https://example.com"})
    assert res.status_code == 401


async def test_private_target_rejected_by_default(client: AsyncClient) -> None:
    await register_login(client, "a@example.com")
    res = await client.post("/api/targets", json={"name": "Local", "url": "http://127.0.0.1:9/"})
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "rejected"
    assert "private" in body["validation_message"].lower()
    ready = await client.get(f"/api/targets/{body['id']}/readiness")
    assert ready.json()["auditable"] is False


async def test_credentials_in_url_are_rejected(client: AsyncClient) -> None:
    await register_login(client, "b@example.com")
    res = await client.post(
        "/api/targets", json={"name": "x", "url": "https://user:pass@example.com"}
    )
    assert res.status_code == 422


async def test_audit_blocked_until_authorized(
    client: AsyncClient, allow_private: None, local_target_url: str
) -> None:
    await register_login(client, "c@example.com")
    res = await client.post("/api/targets", json={"name": "Local", "url": local_target_url})
    assert res.json()["status"] == "validated"
    target_id = res.json()["id"]
    start = await client.post(f"/api/targets/{target_id}/audits")
    assert start.status_code == 400  # not authorized yet
    other = await client.post(f"/api/targets/{target_id}/authorize", json={"confirmed": False})
    assert other.status_code == 400  # must be explicitly true, not just present


async def test_live_audit_runs_end_to_end_against_a_real_local_server(
    client: AsyncClient, allow_private: None, local_target_url: str, inline_runner: None
) -> None:
    await register_login(client, "d@example.com")
    created = await client.post("/api/targets", json={"name": "Local app", "url": local_target_url})
    assert created.json()["status"] == "validated"
    target_id = created.json()["id"]
    auth = await client.post(f"/api/targets/{target_id}/authorize", json={"confirmed": True})
    assert auth.status_code == 200

    started = await client.post(f"/api/targets/{target_id}/audits")
    assert started.status_code == 202
    audit_id = started.json()["id"]

    detail = await client.get(f"/api/audits/{audit_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["status"] == "completed", body
    assert body["audit_type"] == "live"

    findings = (await client.get(f"/api/audits/{audit_id}/findings")).json()
    # The server sends no CSP/HSTS/X-Content-Type-Options/X-Frame-Options: the deterministic
    # passive checks (no ZAP/Nuclei needed) must have found at least one of them for real.
    types = {f["type"] for f in findings}
    assert types & {
        "missing_content_security_policy_header",
        "missing_strict_transport_security_header",
        "missing_x_content_type_options_header",
        "missing_x_frame_options_header",
    }, findings
    # At least one must have been *confirmed* by the genuinely non-destructive re-fetch --
    # the first time this project has ever produced an honestly "confirmed" finding.
    assert any(f["status"] == "confirmed" for f in findings), findings

    logs = (await client.get(f"/api/audits/{audit_id}/logs")).json()
    stages = {log["action"] for log in logs}
    assert {"started", "completed"} <= stages

    audits_for_target = await client.get(f"/api/targets/{target_id}/audits")
    assert len(audits_for_target.json()) == 1


async def test_owner_isolation(
    client: AsyncClient, allow_private: None, local_target_url: str
) -> None:
    await register_login(client, "e1@example.com")
    mine = await client.post("/api/targets", json={"name": "Mine", "url": local_target_url})
    target_id = mine.json()["id"]

    other_client = client
    # log out and in as a different user, same session cookie jar
    await other_client.post("/api/auth/logout")
    await register_login(other_client, "e2@example.com")
    res = await other_client.get(f"/api/targets/{target_id}")
    assert res.status_code == 404
