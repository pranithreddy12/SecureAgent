"""Workflow-order flaws: a handler moves an entity to a terminal state without checking its
current state (CWE-841, ADR-010).

Typical logic bug: ``POST /orders/<id>/ship`` sets ``order.status = "shipped"`` without verifying
the order was paid, so a client can skip steps (pay -> ship) or replay a step. Detected as: a
request handler assigns a terminal value to a state attribute (``status``, ``paid``, ``shipped``,
...) and nowhere in the handler is any state attribute compared, asserted, or used as a filter.

Heuristic and Python-only; a state machine enforced in the model layer, a database constraint, or a
helper the handler calls (``order.ship()``) is not visible, so findings are "suspicious".
"""

from __future__ import annotations

import ast
import re

from app.analysis.business_logic import LogicFinding
from app.analysis.taint import _dotted, _is_handler, mark_view_handlers

STATE_ATTRS = {
    "status", "state", "step", "stage", "paid", "is_paid", "shipped", "is_shipped",
    "fulfilled", "approved", "is_approved", "completed", "is_completed", "confirmed",
    "delivered", "refunded", "published", "is_published", "verified", "is_verified",
}  # fmt: skip
TERMINAL_VALUES = {
    "paid", "shipped", "approved", "completed", "confirmed", "delivered", "refunded",
    "fulfilled", "published", "closed", "released", "verified", "active",
}  # fmt: skip
_FINALIZING = re.compile(
    r"(?i)(pay|checkout|confirm|ship|fulfil|approve|complete|refund|publish|release|close|verify)"
)
_CHECK_CALL = re.compile(r"(?i)^(can_|ensure_|require_|check_|validate_|assert_|verify_|is_)")


def analyze_workflow(relpath: str, text: str) -> list[LogicFinding]:
    if not relpath.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    mark_view_handlers(tree)
    lines = text.splitlines()
    out: list[LogicFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_handler(node):
            out.extend(_check_handler(node, relpath, lines))
    return out


def _check_handler(func, relpath: str, lines: list[str]) -> list[LogicFinding]:
    assignments = _terminal_assignments(func)
    if not assignments or _has_state_precondition(func):
        return []
    finalizing = bool(_FINALIZING.search(func.name) or _FINALIZING.search(_route_path(func)))
    findings = []
    for line, attr, value in assignments[:1]:  # one finding per handler is enough to act on
        evidence = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        findings.append(
            LogicFinding(
                category="workflow_order",
                rule=f"'{attr}' is set to {value!r} without checking the current state",
                severity="medium",
                confidence=0.5 if finalizing else 0.4,
                relpath=relpath,
                line=line,
                handler=func.name,
                field=attr,
                evidence=evidence,
            )
        )
    return findings


def _terminal_assignments(func) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr.lower() in STATE_ATTRS:
                    value = _terminal_value(node.value)
                    if value is not None:
                        hits.append((node.lineno, target.attr, value))
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg and kw.arg.lower() in STATE_ATTRS:
                    value = _terminal_value(kw.value)
                    if value is not None and _is_update_call(node):
                        hits.append((node.lineno, kw.arg, value))
    return sorted(hits)


def _is_update_call(call: ast.Call) -> bool:
    return (_dotted(call.func) or "").rsplit(".", 1)[-1] in {"update", "update_one", "set"}


def _terminal_value(node) -> str | None:
    if isinstance(node, ast.Constant):
        if node.value is True:
            return "True"
        if isinstance(node.value, str) and node.value.lower() in TERMINAL_VALUES:
            return node.value
    if isinstance(node, ast.Attribute) and node.attr.lower() in TERMINAL_VALUES:
        return node.attr  # OrderStatus.PAID
    return None


def _mentions_state(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in STATE_ATTRS:
            return True
        if isinstance(sub, ast.Name) and sub.id.lower() in STATE_ATTRS:
            return True
    return False


def _has_state_precondition(func) -> bool:
    for node in ast.walk(func):
        if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.Assert)) and _mentions_state(
            node.test
        ):
            return True
        if isinstance(node, ast.Compare) and _mentions_state(node):
            return True
        if isinstance(node, ast.Call):
            name = (_dotted(node.func) or "").rsplit(".", 1)[-1]
            if _CHECK_CALL.match(name):
                return True
            # filter_by(status="pending").update(...): the transition is conditional in the query
            if name in {"filter", "filter_by", "where"} and any(
                kw.arg and kw.arg.lower() in STATE_ATTRS for kw in node.keywords
            ):
                return True
            if name in {"filter", "where"} and any(_mentions_state(a) for a in node.args):
                return True
    return False


def _route_path(func) -> str:
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call) and dec.args:
            first = dec.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
    return ""
