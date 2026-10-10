"""SecureAgent as an MCP (Model Context Protocol) server over stdio.

Lets an AI coding assistant (Claude Code, Claude Desktop, Cursor, ...) call the static
analyser directly -- most usefully ``scan_snippet`` to check code it just wrote.

Stdlib only: MCP's stdio transport is newline-delimited JSON-RPC 2.0, small enough to
implement directly, which keeps the installable scanner dependency-light (ADR-009).

Safety:
- read-only: tools never execute scanned code and never write outside a private temp dir;
- path-confined: ``path`` arguments must live under an allowed root (the working directory, or
  the os.pathsep-separated ``SECUREAGENT_MCP_ROOTS``); symlink escapes are resolved first;
- offline by default: the OSV lookup (network) only runs when a call asks for it.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

SERVER_NAME = "secureagent"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL = "2025-06-18"
MAX_FINDINGS = 200
MAX_SNIPPET_BYTES = 200_000
_SAFE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

TOOLS = [
    {
        "name": "scan_snippet",
        "description": (
            "Statically analyse a code snippet for security flaws (injection, authz, secrets, "
            "business-logic). Use it to check code you just wrote. Read-only; nothing is executed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Source code to analyse."},
                "filename": {
                    "type": "string",
                    "description": "Name with extension (app.py, server.js). Default app.py.",
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "scan_path",
        "description": (
            "Statically analyse a source directory (read-only). Returns findings with severity, "
            "CWE/OWASP mapping and remediation. Honest statuses: never 'confirmed'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to scan."},
                "exclude": {"type": "array", "items": {"type": "string"}},
                "intent": {"type": "string", "description": "Path to a secureagent-intent.json."},
                "include_osv": {
                    "type": "boolean",
                    "description": "Also query OSV for known-vulnerable dependencies (network).",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "authorization_matrix",
        "description": "Route x guard grid for a source directory, grouped by resource.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


class ToolError(Exception):
    """A tool call failed in a way the caller should see (returned as isError)."""


def allowed_roots() -> list[Path]:
    raw = os.environ.get("SECUREAGENT_MCP_ROOTS")
    roots = [p for p in raw.split(os.pathsep) if p] if raw else [os.getcwd()]
    return [Path(r).resolve() for r in roots]


def confine(path: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    for root in allowed_roots():
        if resolved == root or root in resolved.parents:
            return resolved
    raise ToolError(
        f"path is outside the allowed roots ({', '.join(str(r) for r in allowed_roots())}); "
        "set SECUREAGENT_MCP_ROOTS to widen it"
    )


def _findings_payload(result, limit: int = MAX_FINDINGS) -> dict[str, Any]:
    from app.analysis.reporting import scan_to_report_context

    findings = scan_to_report_context(result).findings
    items = [
        {
            "title": f.title,
            "type": f.type,
            "severity": f.severity.value,
            "status": f.status.value,
            "confidence": round(f.confidence, 2),
            "location": f.endpoint,
            "cwe": f.cwe,
            "owasp": f.owasp_category,
            "cve": f.cve,
            "evidence": f.evidence,
            "remediation": f.remediation,
        }
        for f in findings[:limit]
    ]
    return {
        "files_scanned": result.stats.files_scanned,
        "total_findings": len(findings),
        "returned": len(items),
        "truncated": len(findings) > limit,
        "severity_counts": {k: v for k, v in result.severity_counts().items() if v},
        "intent_rules_evaluated": result.intent_rules,
        "inline_ignored": result.inline_ignored,
        "osv_note": result.osv_note,
        "findings": items,
        "note": "Static analysis; findings are review items, never confirmed exploits.",
    }


def tool_scan_snippet(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.scanner import scan_repo

    code = args.get("code")
    if not isinstance(code, str) or not code.strip():
        raise ToolError("'code' must be a non-empty string")
    if len(code.encode("utf-8")) > MAX_SNIPPET_BYTES:
        raise ToolError(f"snippet larger than {MAX_SNIPPET_BYTES} bytes")
    name = os.path.basename(str(args.get("filename") or "app.py"))
    if Path(name).suffix.lower() not in _SAFE_SUFFIXES:
        raise ToolError(f"filename must end in one of {sorted(_SAFE_SUFFIXES)}")
    with tempfile.TemporaryDirectory(prefix="secureagent-mcp-") as tmp:
        (Path(tmp) / name).write_text(code, encoding="utf-8")
        result = scan_repo(tmp, check_osv=False)
        return _findings_payload(result)


def tool_scan_path(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.ingest import IngestError
    from app.analysis.intent import IntentError
    from app.analysis.scanner import scan_repo

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    exclude = args.get("exclude") or []
    if not isinstance(exclude, list) or not all(isinstance(e, str) for e in exclude):
        raise ToolError("'exclude' must be a list of strings")
    intent = args.get("intent")
    if intent:
        intent = str(confine(str(intent)))
    try:
        result = scan_repo(
            str(root),
            check_osv=bool(args.get("include_osv", False)),
            exclude=exclude,
            intent=intent,
        )
    except (IngestError, IntentError, OSError) as exc:
        raise ToolError(str(exc)) from exc
    return _findings_payload(result)


def tool_authorization_matrix(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.authz_matrix import build_matrix
    from app.analysis.scanner import scan_repo

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    result = scan_repo(str(root), check_osv=False)
    return {
        "groups": [
            {
                "resource": g.resource,
                "guarded": g.guarded,
                "total": len(g.routes),
                "routes": [
                    {
                        "method": r.method,
                        "path": r.path,
                        "handler": r.handler,
                        "guarded": r.protected,
                        "guard": r.guard,
                        "location": f"{r.relpath}:{r.line}",
                    }
                    for r in g.routes
                ],
            }
            for g in build_matrix(result.routes)
        ]
    }


HANDLERS = {
    "scan_snippet": tool_scan_snippet,
    "scan_path": tool_scan_path,
    "authorization_matrix": tool_authorization_matrix,
}


def _result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle(message: Any) -> dict[str, Any] | None:
    """Process one JSON-RPC message; return the response, or None for notifications."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(None, -32600, "invalid request")
    method = message.get("method")
    req_id = message.get("id")
    is_notification = "id" not in message
    params = message.get("params") or {}

    if method == "initialize":
        version = params.get("protocolVersion") or DEFAULT_PROTOCOL
        return _result(
            req_id,
            {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if is_notification:
        return None  # notifications/initialized, notifications/cancelled, ...
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None:
            return _error(req_id, -32602, f"unknown tool: {name}")
        try:
            payload = handler(params.get("arguments") or {})
            return _result(
                req_id, {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}
            )
        except ToolError as exc:
            return _result(
                req_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True}
            )
    return _error(req_id, -32601, f"method not found: {method}")


def serve(stdin=None, stdout=None) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, "parse error")
        else:
            try:
                response = handle(message)
            except Exception as exc:  # noqa: BLE001 - a server must not die on one bad request
                req_id = message.get("id") if isinstance(message, dict) else None
                response = _error(req_id, -32603, f"internal error: {type(exc).__name__}")
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
