"""Spec-first frameworks (connexion, FastAPI-less OpenAPI): handlers named by ``operationId``.

In ``connexion`` / ``flask-restx`` style projects the route table lives in an OpenAPI document and the
Python functions carry no decorator, so decorator-based route detection sees nothing. This module reads
the spec (stdlib only: a small YAML-subset line parser, or ``json``) and returns the operations, from
which the scanner derives (a) the set of handler function names and (b) routes with their
authentication state.

A route is *protected* when its operation, or the document, declares ``security`` with at least one
requirement; an empty list (``security: []``) means explicitly public.
"""

from __future__ import annotations

import json
import re
from contextvars import ContextVar
from dataclasses import dataclass

SPEC_HANDLERS: ContextVar[frozenset[str]] = ContextVar("spec_handlers", default=frozenset())
SPEC_OPERATIONS: ContextVar[tuple] = ContextVar("spec_operations", default=())

_METHODS = ("get", "post", "put", "patch", "delete")


@dataclass(frozen=True)
class SpecOperation:
    method: str
    path: str
    operation_id: str
    secured: bool

    @property
    def function(self) -> str:
        return self.operation_id.rsplit(".", 1)[-1].rsplit(":", 1)[-1]

    @property
    def module(self) -> str:
        head = self.operation_id.rsplit(".", 1)[0] if "." in self.operation_id else ""
        return head.replace(".", "/")


def looks_like_spec(text: str) -> bool:
    return "operationId" in text and bool(re.search(r"(?m)^\s*[\"']?(openapi|swagger)[\"']?\s*:", text))


def parse_spec(relpath: str, text: str) -> list[SpecOperation]:
    if not looks_like_spec(text):
        return []
    if relpath.lower().endswith(".json"):
        return _parse_json(text)
    return _parse_yaml(text)


def _secured(value) -> bool:
    # [{}] means "anonymous allowed"; a non-empty requirement object means authentication
    return isinstance(value, list) and any(bool(v) for v in value)


def _parse_json(text: str) -> list[SpecOperation]:
    try:
        doc = json.loads(text)
    except ValueError:
        return []
    out: list[SpecOperation] = []
    global_secured = _secured(doc.get("security"))
    for path, item in (doc.get("paths") or {}).items():
        for method in _METHODS:
            op = (item or {}).get(method)
            if not isinstance(op, dict) or "operationId" not in op:
                continue
            secured = _secured(op["security"]) if "security" in op else global_secured
            out.append(SpecOperation(method, path, str(op["operationId"]), secured))
    return out


def _parse_yaml(text: str) -> list[SpecOperation]:
    out: list[SpecOperation] = []
    global_secured = False
    in_paths = False
    path = method = None
    op_id = None
    op_secured: bool | None = None
    path_indent = method_indent = 0

    def flush() -> None:
        nonlocal op_id, op_secured
        if path and method and op_id:
            secured = global_secured if op_secured is None else op_secured
            out.append(SpecOperation(method, path, op_id, secured))
        op_id, op_secured = None, None

    lines = text.splitlines()
    for idx, raw in enumerate(lines):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if indent == 0:
            if stripped.startswith("security:"):
                rest = stripped[len("security:") :].strip()
                nxt = next((ln for ln in lines[idx + 1 :] if ln.strip()), "")
                global_secured = rest not in ("[]", "") or nxt.strip().startswith("-")
            in_paths = stripped == "paths:"
            if not in_paths:
                flush()
                path = method = None
            continue
        if not in_paths:
            continue
        m = re.match(r"""^["']?(/[^"':]*)["']?\s*:\s*$""", stripped)
        if m and (path is None or indent <= path_indent):
            flush()
            path, method, path_indent = m.group(1), None, indent
            continue
        m = re.match(r"^(get|post|put|patch|delete)\s*:\s*$", stripped)
        if m and path is not None and indent > path_indent:
            flush()
            method, method_indent = m.group(1), indent
            continue
        if method is not None and indent > method_indent:
            if stripped.startswith("operationId:"):
                op_id = stripped.split(":", 1)[1].strip().strip("\"'")
            elif stripped.startswith("security:"):
                rest = stripped[len("security:") :].strip()
                nxt = next((ln for ln in lines[idx + 1 :] if ln.strip()), "")
                op_secured = rest not in ("[]",) and (rest != "" or nxt.strip().startswith("-"))
    flush()
    return out


def locate_handler(op: SpecOperation, sources: list[tuple[str, str]]) -> tuple[str, int] | None:
    """The ``(relpath, line)`` of the Python function an operation points at, or ``None``."""
    pattern = re.compile(r"(?m)^\s*(?:async\s+)?def\s+" + re.escape(op.function) + r"\s*\(")
    module = op.module
    candidates = []
    for relpath, text in sources:
        if not relpath.endswith(".py"):
            continue
        stem = relpath[:-3]
        if module and not (stem == module or stem.endswith("/" + module)):
            continue
        m = pattern.search(text)
        if m:
            candidates.append((relpath, text.count("\n", 0, m.start()) + 1))
    return candidates[0] if len(candidates) >= 1 else None
