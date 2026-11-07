# ruff: noqa: E501  (the sample application below is realistic code, not wrapped for the linter)
"""Detectors for applications built on LLMs and agents: LLM output reaching sinks (OWASP LLM05),
request data in system prompts (LLM01), MCP / agent tool arguments as untrusted input, and MCP
client configs / browser-exposed LLM keys."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.misconfig import scan_misconfig
from app.analysis.scanner import scan_repo
from app.analysis.taint import analyze_taint

LLM_APP = """
from openai import OpenAI
import anthropic
client = OpenAI()
claude = anthropic.Anthropic()

def generate_and_run(question):
    resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}])
    code = resp.choices[0].message.content
    eval(code)

def summarize(text):
    out = claude.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": text}])
    return out.content[0].text

@app.post("/chat")
def chat(request):
    persona = request.json["persona"]
    msg = request.json["msg"]
    client.chat.completions.create(
        model="m",
        messages=[{"role": "system", "content": "You are " + persona}, {"role": "user", "content": msg}],
    )
    claude.messages.create(model="m", max_tokens=10, system="Be brief.", messages=[{"role": "user", "content": msg}])
    claude.messages.create(model="m", max_tokens=10, system=persona, messages=[])
"""


def _by_type(findings):
    out: dict[str, list] = {}
    for f in findings:
        out.setdefault(f.vuln_type, []).append(f)
    return out


def test_llm_output_into_eval_is_flagged_with_an_llm_source() -> None:
    hits = _by_type(analyze_taint("app.py", LLM_APP))
    [f] = hits["code_injection"]
    assert f.line == 10
    assert "LLM output: untrusted" in f.path[0]


def test_request_data_in_system_prompt_is_prompt_injection() -> None:
    hits = _by_type(analyze_taint("app.py", LLM_APP))
    lines = sorted(f.line for f in hits["prompt_injection"])
    assert lines == [20, 25]  # system message + system= kwarg; the user-role messages are fine


def test_returning_llm_output_from_a_helper_is_not_a_finding() -> None:
    hits = _by_type(analyze_taint("app.py", LLM_APP))
    assert all(f.line != 14 for fs in hits.values() for f in fs)


def test_invoke_is_an_llm_call_only_with_langchain_imported() -> None:
    body = "def f(chain, q):\n    out = chain.invoke(q)\n    eval(out)\n"
    assert analyze_taint("a.py", body) == []
    hits = analyze_taint("a.py", "from langchain_openai import ChatOpenAI\n" + body)
    assert [f.vuln_type for f in hits] == ["code_injection"]


def test_mcp_and_agent_tool_arguments_are_untrusted() -> None:
    code = """
import subprocess
from langchain_core.tools import tool

@mcp.tool()
def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout

@tool
def read_file(path: str) -> str:
    return open(path).read()

def not_a_tool(cmd):
    subprocess.run(cmd, shell=True)
"""
    hits = _by_type(analyze_taint("server.py", code))
    [cmd] = hits["command_injection"]
    assert cmd.line == 7 and "chosen by an LLM" in cmd.path[0]
    assert [f.line for f in hits["path_traversal"]] == [11]


def test_mcp_config_rules() -> None:
    cfg = json.dumps(
        {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]},
                "gh": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github@1.2.0"],
                },
                "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                "time": {"command": "uvx", "args": ["mcp-server-time==0.6.2"]},
                "remote": {"url": "http://mcp.example.com/sse"},
                "local": {"url": "http://localhost:3000/mcp"},
            }
        },
        indent=2,
    )
    found = {(f.category, f.rule.split("'")[1]) for f in scan_misconfig(".cursor/mcp.json", cfg)}
    assert found == {
        ("mcp_unpinned_server", "fs"),
        ("mcp_unpinned_server", "fetch"),
        ("mcp_insecure_transport", "remote"),
    }
    assert scan_misconfig("package.json", cfg) == []  # only MCP config files are read this way


def test_llm_key_exposed_to_browser() -> None:
    env = "NEXT_PUBLIC_OPENAI_API_KEY=sk-x\nOPENAI_API_KEY=sk-y\nNEXT_PUBLIC_SITE_URL=x\n"
    assert [f.line for f in scan_misconfig("web/.env.local", env)] == [1]
    ts = "const c = new OpenAI({ apiKey, dangerouslyAllowBrowser: true })"
    assert [f.category for f in scan_misconfig("web/ai.ts", ts)] == ["llm_key_in_browser"]


def test_scan_repo_reads_mcp_config_in_hidden_editor_dirs(tmp_path: Path) -> None:
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(
        json.dumps({"servers": {"x": {"command": "npx", "args": ["some-mcp"]}}}), encoding="utf-8"
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    assert [f.category for f in result.misconfig_findings] == ["mcp_unpinned_server"]
