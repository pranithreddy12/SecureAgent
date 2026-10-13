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

import hashlib
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
DEFAULT_PAGE = 25
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
_PRUNE = {".git", "node_modules", ".venv", "venv", "__pycache__", ".next", "dist", "build", ".tox"}
_SIGNATURE_FILE_CAP = 100_000
_CACHE_SIZE = 6

INSTRUCTIONS = (
    "SecureAgent is a deterministic, read-only static analyser. Findings are REVIEW ITEMS, "
    "never confirmed vulnerabilities. Workflow: scan_path (a short, severity-ordered page) -> "
    "explain_finding for any item you will report -> judge it from the code -> state only what "
    "the evidence supports. Each finding carries `impact_ceiling` (the worst realistic outcome "
    "of that kind of finding) and `not_claimed` (what it does NOT establish): never report a "
    "finding as worse than its ceiling and never claim exploitation. If the code shows a "
    "finding is not real, say so. Results are cached while the files are unchanged. Detector "
    "coverage is listed in `coverage` of every scan."
)

# What the detectors do and do not look at; returned with every scan so silence is not safety.
COVERAGE = {
    "languages": {"python": "AST + taint (deep)", "javascript/typescript": "regex (shallow)"},
    "checked": [
        "hardcoded secrets and secret fallbacks",
        "known-vulnerable dependencies (when include_osv)",
        "injection (sql, command, code, ssrf, path, redirect)",
        "unsafe parsing/deserialization/TLS/hash",
        "access control (unguarded routes, idor, inconsistent guards)",
        "business logic (mass assignment, trusted client values, workflow order, intent rules)",
        "misconfiguration (debug, cors, csrf, jwt, cookies)",
    ],
    "not_checked": [
        "runtime behaviour, deployed configuration and infrastructure",
        "global middleware / gateway authentication (invisible to static analysis)",
        "languages other than Python and JS/TS",
        "dependency reachability",
    ],
}
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
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                },
            },
            "required": ["code"],
        },
    },
    {
        "name": "scan_path",
        "description": (
            "Statically analyse a source directory (read-only). Returns a severity-ordered PAGE of "
            "findings (narrow with cursor/limit/min_severity/types/file), each with its "
            "impact_ceiling and not_claimed, plus per-type counts and the detector coverage. "
            "Findings are review items, never confirmed. Call explain_finding before reporting one."
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
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "informational"],
                    "description": "Only findings at or above this severity.",
                },
                "types": {"type": "array", "items": {"type": "string"}},
                "file": {
                    "type": "string",
                    "description": "Only findings whose location contains this.",
                },
                "status": {
                    "type": "string",
                    "enum": ["likely", "suspicious", "informational", "false_positive"],
                },
                "limit": {"type": "integer", "description": "Page size (default 25, max 200)."},
                "cursor": {
                    "type": "integer",
                    "description": "Offset: next_cursor from the previous page.",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "suggest_fixes",
        "description": (
            "Propose verified patches (unified diffs) for findings with a deterministic fix "
            "(weak hash, TLS verification, yaml.load, debug flag, CSRF, JWT verification, "
            "hardcoded secret). Pass `id` for just one finding. Never writes files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "id": {"type": "string", "description": "finding id to patch (optional)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "explain_finding",
        "description": (
            "Everything needed to judge ONE finding: the enclosing function, the helpers it calls, "
            "the numbered source-to-sink taint path, the remediation, its impact_ceiling, what it "
            "does NOT claim, and `verify_with` questions that settle it from the code. Pass the "
            "`id` from scan results. Secret values are redacted. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "id": {"type": "string", "description": "finding id (8+ hex chars) from a scan"},
            },
            "required": ["path", "id"],
        },
    },
    {
        "name": "scan_diff",
        "description": (
            "Findings that are NEW compared with a git ref (branch, tag or commit), by "
            "line-independent fingerprint. Use it to review a change instead of a whole repo."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "since": {"type": "string", "description": "git ref, e.g. origin/main or HEAD~1"},
            },
            "required": ["path", "since"],
        },
    },
    {
        "name": "application_model",
        "description": (
            "Static reconnaissance of a source directory: technologies, inputs read (query/body/"
            "path/header/cookie names), outbound hosts and environment variables. Reads files "
            "only; never contacts a running system."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
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


RECORD_VERDICT_TOOL = {
    "name": "record_verdict",
    "description": (
        "Record that a finding is a FALSE POSITIVE, with a justification, in the project's "
        "secureagent-suppressions.json (a reviewable file; the finding becomes false_positive on "
        "the next scan, never deleted). Only after explain_finding and only when the code proves "
        "it. "
        "Requires the server to be started with SECUREAGENT_MCP_WRITE=1."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "The scanned project directory."},
            "id": {"type": "string", "description": "finding id from a scan"},
            "reason": {"type": "string", "description": "Why it is not real (>= 10 characters)."},
            "expires": {"type": "string", "description": "Optional YYYY-MM-DD review date."},
        },
        "required": ["path", "id", "reason"],
    },
}

PROMPTS = [
    {
        "name": "security_review",
        "description": "Review a project's security: scan, verify each finding, report honestly.",
        "arguments": [
            {"name": "path", "description": "Project directory to review.", "required": True}
        ],
    }
]


def _write_enabled() -> bool:
    return os.environ.get("SECUREAGENT_MCP_WRITE") == "1"


def _tools() -> list[dict[str, Any]]:
    return TOOLS + ([RECORD_VERDICT_TOOL] if _write_enabled() else [])


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


_cache: dict[tuple, tuple[Any, Any]] = {}  # key -> (ScanResult, ReportContext), insertion = age


def _tree_signature(root: Path) -> str:
    """A cheap fingerprint of the tree (paths, sizes, mtimes) used to reuse a scan."""
    h = hashlib.blake2b(digest_size=20)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _PRUNE)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            h.update(f"{os.path.relpath(full, root)}|{st.st_size}|{st.st_mtime_ns}\n".encode())
            seen += 1
            if seen >= _SIGNATURE_FILE_CAP:
                return h.hexdigest() + "+"
    return h.hexdigest()


def _scan(root: Path, *, exclude=(), osv: bool = False, intent: str | None = None):
    """Scan ``root`` (cached while its files are unchanged). Returns (ScanResult, ReportContext)."""
    from app.analysis.reporting import scan_to_report_context
    from app.analysis.scanner import scan_repo

    key = (str(root), _tree_signature(root), tuple(exclude), osv, intent)
    hit = _cache.get(key)
    if hit is not None:
        return hit
    result = scan_repo(str(root), check_osv=osv, exclude=list(exclude), intent=intent)
    entry = (result, scan_to_report_context(result))
    _cache[key] = entry
    while len(_cache) > _CACHE_SIZE:
        _cache.pop(next(iter(_cache)))
    return entry


def _find_finding(root: Path, wanted: str):
    """The finding whose id starts with ``wanted`` (a cached scan of this tree, else a new one)."""
    from app.analysis.baseline import fingerprint

    sig = _tree_signature(root)
    pools = [ctx for (r, s, *_), (_, ctx) in _cache.items() if r == str(root) and s == sig]
    pools.append(_scan(root)[1])
    for ctx in pools:
        matches = {fingerprint(f): f for f in ctx.findings if fingerprint(f).startswith(wanted)}
        if len(matches) > 1:
            raise ToolError(f"id {wanted!r} is ambiguous; use more characters")
        if matches:
            return next(iter(matches.values()))
    raise ToolError(f"no finding with id {wanted!r}; re-run scan_path for current ids")


def _sev_rank(value: str) -> int:
    return _SEVERITY_ORDER.index(value) if value in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _item(f) -> dict[str, Any]:
    from app.analysis.baseline import fingerprint
    from app.analysis.guidance import guidance_for

    g = guidance_for(f.type)
    return {
        "id": fingerprint(f)[:8],
        "title": f.title,
        "type": f.type,
        "severity": f.severity.value,
        "status": f.status.value,
        "confidence": round(f.confidence, 2),
        "location": f.endpoint,
        "status_reason": f.status_reason,
        "impact_ceiling": g["impact_ceiling"],
        "not_claimed": g["not_claimed"],
        "cwe": f.cwe,
        "owasp": f.owasp_category,
        "cve": f.cve,
        "evidence": f.evidence,
        "remediation": f.remediation,
    }


def _findings_payload(result, ctx=None, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """A severity-ordered, filterable, paged view of a scan (``args``: the tool arguments)."""
    from app.analysis.reporting import scan_to_report_context

    args = args or {}
    ctx = ctx or scan_to_report_context(result)
    findings = ctx.findings

    min_sev = args.get("min_severity")
    if min_sev is not None and min_sev not in _SEVERITY_ORDER:
        raise ToolError(f"'min_severity' must be one of {_SEVERITY_ORDER}")
    types = args.get("types")
    if types is not None and not (
        isinstance(types, list) and all(isinstance(t, str) for t in types)
    ):
        raise ToolError("'types' must be a list of strings")
    file_part = args.get("file")
    status = args.get("status")
    try:
        limit = max(1, min(int(args.get("limit", DEFAULT_PAGE)), MAX_FINDINGS))
        offset = max(0, int(args.get("cursor", 0) or 0))
    except (TypeError, ValueError):
        raise ToolError("'limit' and 'cursor' must be integers") from None

    def keep(f) -> bool:
        return (
            (min_sev is None or _sev_rank(f.severity.value) <= _sev_rank(min_sev))
            and (not types or f.type in types)
            and (not file_part or file_part in f.endpoint)
            and (not status or f.status.value == status)
        )

    ordered = sorted(
        findings, key=lambda f: (_sev_rank(f.severity.value), -f.confidence, f.endpoint)
    )
    matched = [f for f in ordered if keep(f)]
    page = matched[offset : offset + limit]
    items = [_item(f) for f in page]
    by_type: dict[str, int] = {}
    for f in findings:
        by_type[f.type] = by_type.get(f.type, 0) + 1
    next_cursor = offset + limit if offset + limit < len(matched) else None
    return {
        "files_scanned": result.stats.files_scanned,
        "total_findings": len(findings),
        "matching": len(matched),
        "returned": len(items),
        "truncated": next_cursor is not None,
        "next_cursor": next_cursor,
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "severity_counts": {k: v for k, v in result.severity_counts().items() if v},
        "intent_rules_evaluated": result.intent_rules,
        "inline_ignored": result.inline_ignored,
        "osv_note": result.osv_note,
        "attack_chains": [c.model_dump(mode="json") for c in ctx.attack_chains],
        "findings": items,
        "coverage": COVERAGE,
        "note": "Static analysis; findings are review items, never confirmed exploits. "
        "Do not exceed a finding's impact_ceiling.",
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
        return _findings_payload(result, args=args)


def tool_scan_path(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.ingest import IngestError
    from app.analysis.intent import IntentError

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
        result, ctx = _scan(
            root,
            exclude=exclude,
            osv=bool(args.get("include_osv", False)),
            intent=intent,
        )
    except (IngestError, IntentError, OSError) as exc:
        raise ToolError(str(exc)) from exc
    return _findings_payload(result, ctx, args)


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


def tool_suggest_fixes(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.fixes import propose_fixes

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    findings = _scan(root)[1].findings
    wanted = str(args.get("id", "")).strip().lower()
    if wanted:  # only the patch for one finding
        findings = [_find_finding(root, wanted)]
    patches = propose_fixes(str(root), findings)
    return {
        "patches": [
            {
                "file": p.path,
                "verified": p.verified,
                "verification": p.note,
                "changes": [
                    {
                        "line": c.line,
                        "type": c.finding_type,
                        "what": c.description,
                        "check": c.caveat,
                    }
                    for c in p.changes
                ],
                "diff": p.diff,
            }
            for p in patches
        ],
        "note": "Suggestions only; nothing was written. Review each caveat before applying.",
    }


def tool_explain_finding(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis import llm_review as lr
    from app.analysis.baseline import fingerprint
    from app.analysis.guidance import guidance_for

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    wanted = str(args.get("id", "")).strip().lower()
    if len(wanted) < 6:
        raise ToolError("'id' must be at least 6 hex characters (see the scan results)")
    f = _find_finding(root, wanted)
    path = lr.evidence_path(f.evidence)
    context = lr.build_context(str(root), f, path)
    g = guidance_for(f.type)
    return {
        "id": fingerprint(f)[:8],
        "title": f.title,
        "type": f.type,
        "severity": f.severity.value,
        "status": f.status.value,
        "status_reason": f.status_reason,
        "location": f.endpoint,
        "impact_ceiling": g["impact_ceiling"],
        "not_claimed": g["not_claimed"],
        "verify_with": g["verify_with"],
        "evidence": f.evidence,
        "taint_path": list(path),
        "remediation": f.remediation,
        "code": context.text if context else None,
        "files": context.files if context else [],
        "note": "Static analysis; judge the code above. Answer the verify_with questions from it, "
        "and do not report more than impact_ceiling.",
    }


def tool_record_verdict(args: dict[str, Any]) -> dict[str, Any]:
    import getpass
    from datetime import date

    from app.analysis.baseline import fingerprint
    from app.analysis.suppressions import FILENAME, MIN_REASON, Suppression, SuppressionError, add

    if not _write_enabled():
        raise ToolError(
            "record_verdict is disabled: start the server with SECUREAGENT_MCP_WRITE=1 to allow "
            "writing secureagent-suppressions.json"
        )
    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    wanted = str(args.get("id", "")).strip().lower()
    if len(wanted) < 6:
        raise ToolError("'id' must be at least 6 hex characters (see the scan results)")
    reason = str(args.get("reason", "")).strip()
    if len(reason) < MIN_REASON:
        raise ToolError(f"'reason' of at least {MIN_REASON} characters is required")
    expires = args.get("expires")
    if expires is not None:
        try:
            date.fromisoformat(str(expires))
        except ValueError:
            raise ToolError("'expires' must be YYYY-MM-DD") from None
    f = _find_finding(root, wanted)
    fp = fingerprint(f)
    same = [x for x in _scan(root)[1].findings if fingerprint(x) == fp]
    try:
        by = f"{getpass.getuser()} (via MCP)"
    except Exception:  # noqa: BLE001 - getuser can raise on odd environments
        by = "mcp"
    entry = Suppression(
        fingerprint=fp,
        type=f.type,
        location=f.endpoint.rsplit(":", 1)[0],
        title=f.title,
        reason=reason,
        by=by,
        created=date.today().isoformat(),
        expires=str(expires) if expires else None,
        count=max(1, len(same)),
    )
    target = root / FILENAME
    try:
        add(str(target), entry)
    except (SuppressionError, OSError, ValueError) as exc:
        raise ToolError(str(exc)) from exc
    return {
        "recorded": True,
        "id": fp[:8],
        "file": str(target),
        "count": entry.count,
        "expires": entry.expires,
        "note": "The finding becomes false_positive on the next scan. Review and commit this file; "
        "it is the audit trail for the decision.",
    }


def tool_scan_diff(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.baseline import fingerprint
    from app.analysis.gitdiff import GitDiffError, base_fingerprints, split_new
    from app.analysis.reporting import scan_to_report_context
    from app.analysis.scanner import scan_repo

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    ref = str(args.get("since", "")).strip()
    if not ref:
        raise ToolError("'since' must be a git ref")

    def scan(p: str):
        return scan_repo(p, check_osv=False)

    def findings(r):
        return scan_to_report_context(r).findings

    try:
        base = base_fingerprints(str(root), ref, scan, fingerprint, findings)
    except GitDiffError as exc:
        raise ToolError(str(exc)) from exc
    current = scan(str(root))
    items = [(fingerprint(f), f) for f in findings(current)]
    new, unchanged = split_new(items, base)
    payload = _findings_payload(current)
    wanted = {(f.endpoint, f.title) for _, f in new}
    payload["findings"] = [x for x in payload["findings"] if (x["location"], x["title"]) in wanted]
    payload["total_findings"] = len(new)
    payload["returned"] = len(payload["findings"])
    payload["since"] = ref
    payload["unchanged_hidden"] = len(unchanged)
    return payload


def tool_application_model(args: dict[str, Any]) -> dict[str, Any]:
    from app.analysis.scanner import scan_repo

    root = confine(str(args.get("path", "")))
    if not root.is_dir():
        raise ToolError(f"not a directory: {root}")
    result = scan_repo(str(root), check_osv=False)
    return {
        **result.app_model.summary(),
        "routes": len(result.routes),
        "guarded_routes": sum(1 for r in result.routes if r.protected),
        "note": "Static model from source files; no running system was contacted.",
    }


HANDLERS = {
    "scan_snippet": tool_scan_snippet,
    "scan_path": tool_scan_path,
    "suggest_fixes": tool_suggest_fixes,
    "scan_diff": tool_scan_diff,
    "explain_finding": tool_explain_finding,
    "application_model": tool_application_model,
    "authorization_matrix": tool_authorization_matrix,
    "record_verdict": tool_record_verdict,
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
                "capabilities": {"tools": {}, "prompts": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": INSTRUCTIONS,
            },
        )
    if is_notification:
        return None  # notifications/initialized, notifications/cancelled, ...
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": _tools()})
    if method == "prompts/list":
        return _result(req_id, {"prompts": PROMPTS})
    if method == "prompts/get":
        if params.get("name") != "security_review":
            return _error(req_id, -32602, f"unknown prompt: {params.get('name')}")
        path = str((params.get("arguments") or {}).get("path") or ".")
        text = (
            f"Review the security of {path} using the secureagent tools.\n"
            "1. scan_path on it; read `coverage` and `by_type` first.\n"
            "2. For each of the top findings call explain_finding and answer its verify_with "
            "questions from the code.\n"
            "3. Report each as real, not real, or needs-a-human, never above its impact_ceiling, "
            "and say what static analysis cannot show.\n"
            "4. Offer suggest_fixes (by id) for the real ones."
        )
        return _result(
            req_id,
            {"messages": [{"role": "user", "content": {"type": "text", "text": text}}]},
        )
    if method == "tools/call":
        name = params.get("name")
        handler = HANDLERS.get(name)
        if handler is None or (name == "record_verdict" and not _write_enabled()):
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
