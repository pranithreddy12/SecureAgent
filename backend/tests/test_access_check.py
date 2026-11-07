"""Two-account cross-account access check (BOLA): verdict logic with a fake fetcher, input
validation, and a real end-to-end live audit against a local server with a planted BOLA bug."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from httpx import AsyncClient

from app.schemas.pipeline import TargetScope
from app.tools.access_check import (
    AccessCheckConfig,
    AccessCheckError,
    check_object,
    parse_config,
    to_findings,
)
from app.tools.http import HttpResponse
from app.tools.policy import PolicyError, RequestContext
from tests.test_targets import (  # noqa: F401 - fixtures
    allow_private,
    inline_runner,
    register_login,
)

CTX = RequestContext(authorized=True, scope=TargetScope())
CFG = AccessCheckConfig({"Cookie": "s=a"}, {"Cookie": "s=b"}, ["http://t/x"])
A_BODY = b'{"id": 1, "owner": "alice", "card": "4111"}'


def _fetcher(by_who: dict[str, tuple[int, bytes]]):
    def fetch(url, ctx, headers):
        who = {"s=a": "a", "s=b": "b"}.get(headers.get("Cookie", ""), "anon")
        status, body = by_who[who]
        return HttpResponse(url, status, {}, body)

    return fetch


@pytest.mark.parametrize(
    ("responses", "verdict"),
    [
        ({"a": (200, A_BODY), "anon": (401, b""), "b": (200, A_BODY)}, "exposed"),
        ({"a": (200, A_BODY), "anon": (401, b""), "b": (404, b"nope")}, "enforced"),
        ({"a": (200, A_BODY), "anon": (200, A_BODY), "b": (200, A_BODY)}, "public"),
        ({"a": (403, b"no"), "anon": (401, b""), "b": (200, A_BODY)}, "not_owned"),
        (
            {"a": (200, A_BODY), "anon": (401, b""), "b": (200, b'{"id": 9, "x": 1}')},
            "inconclusive",
        ),
    ],
)
def test_verdicts(responses, verdict) -> None:
    assert check_object("http://t/x", CFG, CTX, _fetcher(responses)).verdict == verdict


def test_policy_block_is_reported_not_raised() -> None:
    def blocked(url, ctx, headers):
        raise PolicyError("URL is outside the authorized scope")

    out = check_object("http://elsewhere/x", CFG, CTX, blocked)
    assert out.verdict == "blocked" and "outside" in out.note


def test_only_exposed_objects_become_confirmed_findings_without_secrets() -> None:
    exposed = check_object(
        "http://t/orders/1",
        CFG,
        CTX,
        _fetcher({"a": (200, A_BODY), "anon": (401, b""), "b": (200, A_BODY)}),
    )
    enforced = check_object(
        "http://t/orders/2",
        CFG,
        CTX,
        _fetcher({"a": (200, A_BODY), "anon": (401, b""), "b": (403, b"")}),
    )
    findings, results = to_findings([exposed, enforced])
    assert [f["endpoint"] for f in findings] == ["http://t/orders/1"]
    assert results[0]["validated"] is True
    blob = json.dumps([findings, results])
    assert "s=a" not in blob and "s=b" not in blob and "4111" not in blob  # no creds, no bodies


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"user_a": {"Cookie": "a"}, "user_b": {"Cookie": "b"}, "urls": []}, "at least one URL"),
        ({"user_a": {"Host": "x"}, "user_b": {"Cookie": "b"}, "urls": ["u"]}, "not allowed"),
        ({"user_a": {"Cookie": "a\r\nX: y"}, "user_b": {"Cookie": "b"}, "urls": ["u"]}, "invalid"),
        ({"user_a": {"Cookie": "a"}, "user_b": {"Cookie": "a"}, "urls": ["u"]}, "different"),
    ],
)
def test_config_validation(raw, message) -> None:
    with pytest.raises(AccessCheckError, match=message):
        parse_config(raw)
    assert parse_config(None) is None


class _BolaApp(BaseHTTPRequestHandler):
    """/orders/1 has the bug (any logged-in user reads it); /orders/2 checks the owner."""

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        user = {"session=alice": "alice", "session=bob": "bob"}.get(self.headers.get("Cookie"))
        if self.path.startswith("/orders/") and user is None:
            status, body = 401, b'{"error": "login"}'
        elif self.path == "/orders/1":
            status, body = 200, b'{"id": 1, "owner": "alice", "total": 42.5, "items": [1, 2]}'
        elif self.path == "/orders/2":
            ok = user == "alice"
            status = 200 if ok else 404
            body = b'{"id": 2, "owner": "alice", "total": 9.0}' if ok else b'{"error": "none"}'
        else:
            status, body = 200, b"<html><body>shop</body></html>"
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def bola_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BolaApp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.mark.anyio
async def test_live_audit_confirms_planted_bola(
    client: AsyncClient,
    allow_private: None,  # noqa: F811
    bola_url: str,
    inline_runner: None,  # noqa: F811
) -> None:
    await register_login(client, "bola@example.com")
    target = (
        await client.post("/api/targets", json={"name": "Shop", "url": bola_url + "/"})
    ).json()
    await client.post(f"/api/targets/{target['id']}/authorize", json={"confirmed": True})

    bad = await client.post(
        f"/api/targets/{target['id']}/audits",
        json={
            "access_check": {"user_a": {"Cookie": "x"}, "user_b": {"Cookie": "x"}, "urls": ["u"]}
        },
    )
    assert bad.status_code == 422

    started = await client.post(
        f"/api/targets/{target['id']}/audits",
        json={
            "access_check": {
                "user_a": {"Cookie": "session=alice"},
                "user_b": {"Cookie": "session=bob"},
                "urls": [f"{bola_url}/orders/1", f"{bola_url}/orders/2"],
            }
        },
    )
    assert started.status_code == 202
    audit_id = started.json()["id"]
    detail = (await client.get(f"/api/audits/{audit_id}")).json()
    assert detail["status"] == "completed", detail
    summary = detail["stage_state"]["access_control_check"]
    assert summary["verdicts"] == {"exposed": 1, "enforced": 1}
    assert "session=alice" not in json.dumps(detail)

    findings = (await client.get(f"/api/audits/{audit_id}/findings")).json()
    bola = [f for f in findings if f["type"] == "bola"]
    assert [(f["endpoint"], f["status"]) for f in bola] == [(f"{bola_url}/orders/1", "confirmed")]


@pytest.mark.anyio
async def test_failed_live_audit_resumes_from_the_failed_stage(
    client: AsyncClient,
    allow_private: None,  # noqa: F811
    bola_url: str,
    inline_runner: None,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.agents import reconnaissance_agent, vulnerability_scanner_agent

    real_recon, real_scan = reconnaissance_agent.run, vulnerability_scanner_agent.run
    calls = {"recon": 0}

    async def counting_recon(state):
        calls["recon"] += 1
        return await real_recon(state)

    async def broken_scan(state):
        raise RuntimeError("ZAP fell over")

    monkeypatch.setattr(reconnaissance_agent, "run", counting_recon)
    monkeypatch.setattr(vulnerability_scanner_agent, "run", broken_scan)

    await register_login(client, "resume@example.com")
    target = (await client.post("/api/targets", json={"name": "S", "url": bola_url + "/"})).json()
    await client.post(f"/api/targets/{target['id']}/authorize", json={"confirmed": True})
    audit_id = (await client.post(f"/api/targets/{target['id']}/audits")).json()["id"]
    failed = (await client.get(f"/api/audits/{audit_id}")).json()
    assert failed["status"] == "failed"
    assert "report_generation" not in failed["stage_state"]  # nothing ran after the failure

    monkeypatch.setattr(vulnerability_scanner_agent, "run", real_scan)
    res = await client.post(f"/api/audits/{audit_id}/retry", params={"resume": True})
    assert res.status_code == 202
    done = (await client.get(f"/api/audits/{audit_id}")).json()
    assert done["status"] == "completed", done
    assert calls["recon"] == 1  # reconnaissance was reused, not repeated
