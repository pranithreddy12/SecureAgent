"""MCP server: protocol behaviour, tool results, and path confinement."""

from __future__ import annotations

import io
import json
import subprocess
import sys

from app import mcp_server
from app.mcp_server import handle, serve


def call(name, arguments=None, req_id=1):
    return handle(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )


def payload(response):
    assert "error" not in response, response
    return json.loads(response["result"]["content"][0]["text"])


def test_initialize_echoes_protocol_and_declares_tools():
    r = handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    )
    assert r["result"]["protocolVersion"] == "2024-11-05"
    assert r["result"]["capabilities"] == {"tools": {}}
    assert r["result"]["serverInfo"]["name"] == "secureagent"


def test_notifications_get_no_response_and_unknown_method_errors():
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    r = handle({"jsonrpc": "2.0", "id": 2, "method": "nope"})
    assert r["error"]["code"] == -32601
    assert handle({"jsonrpc": "1.0", "id": 3, "method": "ping"})["error"]["code"] == -32600


def test_tools_list_matches_handlers():
    r = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == set(mcp_server.HANDLERS)
    for t in r["result"]["tools"]:
        assert t["inputSchema"]["type"] == "object"


def test_scan_snippet_finds_sql_injection():
    code = (
        "from flask import request\n"
        "@app.route('/s')\n"
        "def s():\n"
        "    cur.execute('SELECT * FROM t WHERE n = ' + request.args['n'])\n"
    )
    out = payload(call("scan_snippet", {"code": code}))
    types = {f["type"] for f in out["findings"]}
    assert "sql_injection" in types
    assert all(f["status"] != "confirmed" for f in out["findings"])


def test_scan_snippet_clean_code_and_validation():
    out = payload(call("scan_snippet", {"code": "x = 1\n"}))
    assert out["total_findings"] == 0
    bad = call("scan_snippet", {"code": ""})
    assert bad["result"]["isError"] is True
    bad = call("scan_snippet", {"code": "x", "filename": "payload.exe"})
    assert bad["result"]["isError"] is True


def test_scan_snippet_filename_cannot_escape_temp_dir(tmp_path):
    out = payload(call("scan_snippet", {"code": "x = 1\n", "filename": "../../evil.py"}))
    assert out["files_scanned"] == 1


def test_scan_path_is_confined_to_allowed_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "proj"
    allowed.mkdir()
    (allowed / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    outside = tmp_path / "other"
    outside.mkdir()
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(allowed))

    ok = payload(call("scan_path", {"path": str(allowed)}))
    assert any(f["type"] == "weak_hash" for f in ok["findings"])

    denied = call("scan_path", {"path": str(outside)})
    assert denied["result"]["isError"] is True
    assert "outside the allowed roots" in denied["result"]["content"][0]["text"]

    traversal = call("scan_path", {"path": str(allowed / ".." / "other")})
    assert traversal["result"]["isError"] is True


def test_scan_path_bad_intent_reported_as_tool_error(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
    r = call("scan_path", {"path": str(tmp_path), "intent": str(tmp_path / "bad.json")})
    assert r["result"]["isError"] is True


def test_authorization_matrix_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "app.py").write_text(
        "@app.route('/a')\n@login_required\ndef a():\n    return 1\n", encoding="utf-8"
    )
    out = payload(call("authorization_matrix", {"path": str(tmp_path)}))
    assert out["groups"][0]["resource"] == "a"
    assert out["groups"][0]["routes"][0]["guarded"] is True


def test_unknown_tool_is_a_protocol_error():
    assert call("rm_rf")["error"]["code"] == -32602


def test_serve_handles_garbage_lines_and_keeps_going():
    stdin = io.StringIO(
        "not json\n" + json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}) + "\n\n"
    )
    stdout = io.StringIO()
    assert serve(stdin, stdout) == 0
    lines = [json.loads(ln) for ln in stdout.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1] == {"jsonrpc": "2.0", "id": 7, "result": {}}


def test_stdio_subprocess_roundtrip():
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "app.mcp_server"],
        input=req,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    assert "scan_snippet" in proc.stdout
