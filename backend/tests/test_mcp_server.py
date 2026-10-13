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
    assert r["result"]["capabilities"] == {"tools": {}, "prompts": {}}
    assert r["result"]["serverInfo"]["name"] == "secureagent"


def test_notifications_get_no_response_and_unknown_method_errors():
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    r = handle({"jsonrpc": "2.0", "id": 2, "method": "nope"})
    assert r["error"]["code"] == -32601
    assert handle({"jsonrpc": "1.0", "id": 3, "method": "ping"})["error"]["code"] == -32600


def test_tools_list_matches_handlers():
    r = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert names == set(mcp_server.HANDLERS) - {"record_verdict"}  # write tool is opt-in
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


def test_explain_finding_returns_code_path_and_validates_id(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "@app.route('/s')\n"
        "def s():\n"
        "    name = request.args['n']\n"
        "    cur.execute('SELECT * FROM t WHERE n = ' + name)\n",
        encoding="utf-8",
    )
    scan = payload(call("scan_path", {"path": str(tmp_path)}))
    sqli = next(f for f in scan["findings"] if f["type"] == "sql_injection")
    assert len(sqli["id"]) == 8
    out = payload(call("explain_finding", {"path": str(tmp_path), "id": sqli["id"]}))
    assert out["type"] == "sql_injection" and out["status"] != "confirmed"
    assert "def s():" in out["code"] and out["files"] == ["app.py"]
    assert call("explain_finding", {"path": str(tmp_path), "id": "ffffffff"})["result"]["isError"]
    assert call("explain_finding", {"path": str(tmp_path), "id": "ab"})["result"]["isError"]


# ------------------------------------------------------------------ Phase 1: trustworthy and cheap

SQLI_APP = (
    "from flask import request\n"
    "@app.route('/s')\n"
    "def s():\n"
    "    cur.execute('SELECT * FROM t WHERE n = ' + request.args['n'])\n"
    "import hashlib\nhashlib.md5(b'x')\n"
    "import xml.etree.ElementTree as ET\nET.fromstring(b'<a/>')\n"
)


def test_every_finding_type_has_guidance_and_findings_carry_it(tmp_path, monkeypatch):
    from app.analysis.guidance import DEFAULT, GUIDANCE, guidance_for
    from app.analysis.sinks import CATEGORY_META

    for t in (set(CATEGORY_META) - {"insecure_temp_file"}) | {"sql_injection", "hardcoded_secret"}:
        assert t in GUIDANCE and guidance_for(t) is not DEFAULT, t
    for g in GUIDANCE.values():
        assert g["impact_ceiling"] and g["not_claimed"] and g["verify_with"]

    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    out = payload(call("scan_path", {"path": str(tmp_path)}))
    xml = next(f for f in out["findings"] if f["type"] == "xml_entity_expansion")
    assert "XXE" in xml["not_claimed"] and xml["severity"] == "low"
    assert out["coverage"]["not_checked"] and out["by_type"]["sql_injection"] == 1
    ex = payload(call("explain_finding", {"path": str(tmp_path), "id": xml["id"]}))
    assert ex["verify_with"] and ex["impact_ceiling"].startswith("Denial of service")


def test_initialize_carries_usage_instructions():
    r = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    text = r["result"]["instructions"]
    assert "impact_ceiling" in text and "never confirmed" in text.lower()


def test_scan_path_is_severity_ordered_filterable_and_paged(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    full = payload(call("scan_path", {"path": str(tmp_path)}))
    ranks = ["critical", "high", "medium", "low", "informational"]
    sev = [ranks.index(f["severity"]) for f in full["findings"]]
    assert sev == sorted(sev)
    high = payload(call("scan_path", {"path": str(tmp_path), "min_severity": "high"}))
    assert high["matching"] == 1
    one = payload(call("scan_path", {"path": str(tmp_path), "limit": 1}))
    assert one["returned"] == 1 and one["truncated"] and one["next_cursor"] == 1
    nxt = payload(call("scan_path", {"path": str(tmp_path), "limit": 1, "cursor": 1}))
    assert nxt["findings"][0]["id"] != one["findings"][0]["id"]
    only = payload(call("scan_path", {"path": str(tmp_path), "types": ["weak_hash"]}))
    assert [f["type"] for f in only["findings"]] == ["weak_hash"]
    assert call("scan_path", {"path": str(tmp_path), "min_severity": "bogus"})["result"]["isError"]


def test_scan_is_cached_until_files_change(tmp_path, monkeypatch):
    import app.analysis.scanner as scanner

    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    mcp_server._cache.clear()
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    calls = []
    real = scanner.scan_repo
    monkeypatch.setattr(scanner, "scan_repo", lambda *a, **k: calls.append(1) or real(*a, **k))
    first = payload(call("scan_path", {"path": str(tmp_path)}))
    payload(call("scan_path", {"path": str(tmp_path), "limit": 1}))
    payload(call("explain_finding", {"path": str(tmp_path), "id": first["findings"][0]["id"]}))
    assert len(calls) == 1  # one real scan served three calls
    (tmp_path / "app.py").write_text(SQLI_APP + "x = 1\n", encoding="utf-8")
    payload(call("scan_path", {"path": str(tmp_path)}))
    assert len(calls) == 2  # a changed file invalidates the cache


def test_suggest_fixes_for_one_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    scan = payload(call("scan_path", {"path": str(tmp_path)}))
    weak = next(f for f in scan["findings"] if f["type"] == "weak_hash")
    out = payload(call("suggest_fixes", {"path": str(tmp_path), "id": weak["id"]}))
    types = {c["type"] for p in out["patches"] for c in p["changes"]}
    assert out["patches"] and types == {"weak_hash"}


# ------------------------------------------------------------------ Phase 2: closing the loop


def test_record_verdict_is_opt_in_and_hidden_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    monkeypatch.delenv("SECUREAGENT_MCP_WRITE", raising=False)
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    listed = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    assert "record_verdict" not in {t["name"] for t in listed}
    r = call(
        "record_verdict", {"path": str(tmp_path), "id": "abcdef12", "reason": "long enough reason"}
    )
    assert "error" in r  # unknown tool when writing is not enabled
    assert not (tmp_path / "secureagent-suppressions.json").exists()


def test_record_verdict_round_trip_demotes_the_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(tmp_path))
    monkeypatch.setenv("SECUREAGENT_MCP_WRITE", "1")
    (tmp_path / "app.py").write_text(SQLI_APP, encoding="utf-8")
    listed = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
    assert "record_verdict" in {t["name"] for t in listed}

    scan = payload(call("scan_path", {"path": str(tmp_path)}))
    weak = next(f for f in scan["findings"] if f["type"] == "weak_hash")
    args = {"path": str(tmp_path), "id": weak["id"]}
    short = call("record_verdict", {**args, "reason": "no"})
    assert short["result"]["isError"]
    bad_date = call("record_verdict", {**args, "reason": "a sufficient reason", "expires": "soon"})
    assert bad_date["result"]["isError"]

    out = payload(call("record_verdict", {**args, "reason": "md5 used only as a cache key here"}))
    assert out["recorded"] and (tmp_path / "secureagent-suppressions.json").is_file()

    again = payload(call("scan_path", {"path": str(tmp_path), "types": ["weak_hash"]}))
    assert again["findings"][0]["status"] == "false_positive"
    assert "cache key" in again["findings"][0]["status_reason"]
    # the SQL injection is untouched
    sqli = payload(call("scan_path", {"path": str(tmp_path), "types": ["sql_injection"]}))
    assert sqli["findings"][0]["status"] != "false_positive"


def test_record_verdict_is_confined_to_allowed_roots(tmp_path, monkeypatch):
    allowed = tmp_path / "ok"
    outside = tmp_path / "other"
    allowed.mkdir()
    outside.mkdir()
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(allowed))
    monkeypatch.setenv("SECUREAGENT_MCP_WRITE", "1")
    r = call(
        "record_verdict", {"path": str(outside), "id": "abcdef12", "reason": "long enough reason"}
    )
    assert r["result"]["isError"] and not (outside / "secureagent-suppressions.json").exists()


def test_prompts_list_and_get():
    listed = handle({"jsonrpc": "2.0", "id": 1, "method": "prompts/list"})["result"]["prompts"]
    assert [p["name"] for p in listed] == ["security_review"]
    got = handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "prompts/get",
            "params": {"name": "security_review", "arguments": {"path": "/srv/app"}},
        }
    )
    text = got["result"]["messages"][0]["content"]["text"]
    assert "/srv/app" in text and "explain_finding" in text and "impact_ceiling" in text
    bad = handle({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "x"}})
    assert bad["error"]["code"] == -32602
