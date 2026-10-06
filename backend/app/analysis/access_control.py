"""Detect possible IDOR / broken object-level authorization (OWASP A01, CWE-639).

A handler is flagged when it looks up a record by an identifier taken from the request
(path/query parameter or ``request.*``) but shows no sign of scoping that lookup to the
authenticated user or checking the record's owner. This is the most common real-world
access-control flaw: "fetch object #123" without asking "does this user own #123?".

Static and heuristic: ownership may be enforced by middleware, a base queryset, or code
this intraprocedural check cannot see, so findings are low/medium confidence and status
"suspicious" — never "confirmed". Reuses the taint sources from ``taint.py``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.analysis.taint import (
    SAFE_PARAM_NAMES,
    _all_params,
    _collect_assignments,
    _dotted,
    _expr_tainted,
    _injected_params,
    _is_handler,
)

# ORM-ish receivers for a by-id lookup (reduces false hits on dict/cache .get()).
QUERY_BASES = ("query", "session", "objects", "db", "repository", "repo", "store")
GET_METHODS = {"get", "get_or_404", "get_object_or_404"}
FILTER_METHODS = {"filter", "filter_by", "exclude", "where"}
ID_KEYS = {"id", "pk", "uuid", "guid", "slug", "_id", "oid", "key"}

CURRENT_USER_RE = re.compile(r"(?i)(current_user|request\.user|g\.user|get_current_user|\bowner\b)")
OWNER_ATTRS = {"user_id", "owner_id", "account_id", "tenant_id", "org_id", "user", "owner"}
ADMIN_RE = re.compile(r"(?i)(admin|superuser|staff_member|require_admin)")


@dataclass(frozen=True)
class IdorFinding:
    relpath: str
    line: int
    handler: str
    lookup: str
    severity: str
    confidence: float

    @property
    def cwe(self) -> str:
        return "CWE-639"

    @property
    def owasp(self) -> str:
        return "A01:2021 Broken Access Control"

    @property
    def title(self) -> str:
        return f"Possible IDOR / missing ownership check in {self.handler}()"

    @property
    def remediation(self) -> str:
        return (
            "Scope the lookup to the authenticated user (e.g. filter by current_user) or "
            "verify the record's owner before returning it."
        )


def analyze_access_control(relpath: str, text: str) -> list[IdorFinding]:
    if not relpath.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    findings: list[IdorFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_handler(node):
            _analyze_handler(node, relpath, findings)
    return findings


def _analyze_handler(func, relpath: str, out: list[IdorFinding]) -> None:
    tainted = _tainted_set(func)
    lookups = _by_id_lookups(func, tainted)
    if not lookups:
        return
    if _ownership_scoped(func):
        return
    # Lower confidence if the handler references the current user at all (ownership may
    # be enforced in a way we did not detect); higher if there is no sign of it.
    refs_user = any(
        CURRENT_USER_RE.search(_dotted(n) or "") for n in ast.walk(func) if isinstance(n, ast.expr)
    )
    confidence = 0.4 if refs_user else 0.6
    line, lookup = lookups[0]
    out.append(
        IdorFinding(
            relpath=relpath,
            line=line,
            handler=func.name,
            lookup=lookup,
            severity="high",
            confidence=confidence,
        )
    )


def _tainted_set(func) -> set[str]:
    tainted: set[str] = set()
    injected = _injected_params(func)
    for arg in _all_params(func):
        if arg.arg not in SAFE_PARAM_NAMES and arg.arg not in injected:
            tainted.add(arg.arg)
    assigns = _collect_assignments(func)
    changed = True
    while changed:
        changed = False
        for targets, value in assigns:
            if _expr_tainted(value, tainted):
                for t in targets:
                    if t not in tainted:
                        tainted.add(t)
                        changed = True
    return tainted


def _req(node, tainted: set[str]) -> bool:
    return node is not None and _expr_tainted(node, tainted)


def _by_id_lookups(func, tainted: set[str]) -> list[tuple[int, str]]:
    """Return (line, description) for record-by-request-id lookups with no owner scoping
    in the call itself."""
    hits: list[tuple[int, str]] = []
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        name = _dotted(call.func) or ""
        last = name.rsplit(".", 1)[-1]

        if _scoped_to_user(call):
            continue  # the query itself filters by the current user

        if last in {"get_or_404", "get_object_or_404"} and _any_req(call, tainted):
            hits.append((call.lineno, name or last))
        elif last == "get" and _receiver_is_orm(call.func) and _any_req(call, tainted):
            hits.append((call.lineno, _describe(call.func)))
        elif last in {"filter_by"} and any(
            kw.arg in ID_KEYS and _req(kw.value, tainted) for kw in call.keywords
        ):
            hits.append((call.lineno, name))
        elif last in FILTER_METHODS and _filter_id_eq_request(call, tainted):
            hits.append((call.lineno, name))
    return hits


def _receiver_tokens(node) -> list[str]:
    """Flatten an attribute/call chain into its name tokens (handles .query(...).get)."""
    tokens: list[str] = []
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, ast.Attribute):
            tokens.append(node.attr.lower())
            node = node.value
        elif isinstance(node, ast.Name):
            tokens.append(node.id.lower())
            break
        else:
            break
    return tokens


def _receiver_is_orm(get_attr) -> bool:
    # get_attr is the Attribute node for `.get`; inspect what precedes it.
    receiver = get_attr.value if isinstance(get_attr, ast.Attribute) else get_attr
    tokens = _receiver_tokens(receiver)
    return any(base in tok for tok in tokens for base in QUERY_BASES)


def _describe(get_attr) -> str:
    receiver = get_attr.value if isinstance(get_attr, ast.Attribute) else get_attr
    return ".".join(reversed(_receiver_tokens(receiver))) + ".get"


def _any_req(call: ast.Call, tainted: set[str]) -> bool:
    return any(_req(a, tainted) for a in call.args) or any(
        _req(k.value, tainted) for k in call.keywords
    )


def _filter_id_eq_request(call: ast.Call, tainted: set[str]) -> bool:
    for arg in call.args:
        if isinstance(arg, ast.Compare) and len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq):
            left, right = arg.left, arg.comparators[0]
            left_id = (_dotted(left) or "").rsplit(".", 1)[-1] in ID_KEYS
            right_id = (_dotted(right) or "").rsplit(".", 1)[-1] in ID_KEYS
            if (left_id and _req(right, tainted)) or (right_id and _req(left, tainted)):
                return True
    return False


def _scoped_to_user(call: ast.Call) -> bool:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    if last not in (FILTER_METHODS | GET_METHODS):
        return False
    return any(_is_current_user(sub) for sub in ast.walk(call))


def _ownership_scoped(func) -> bool:
    if _has_admin_guard(func):
        return True
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _scoped_to_user(node):
            return True
        if isinstance(node, ast.Compare) and _ownership_compare(node):
            return True
    return False


def _ownership_compare(node: ast.Compare) -> bool:
    for side in [node.left, *node.comparators]:
        d = _dotted(side) or ""
        if d.rsplit(".", 1)[-1] in OWNER_ATTRS and "." in d:
            return True
    return False


def _is_current_user(node) -> bool:
    d = _dotted(node) or ""
    if not d:
        return False
    if CURRENT_USER_RE.search(d):
        return True
    return d.rsplit(".", 1)[-1] in OWNER_ATTRS


def _has_admin_guard(func) -> bool:
    for dec in func.decorator_list:
        if ADMIN_RE.search(_dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""):
            return True
    for default in list(func.args.defaults) + list(func.args.kw_defaults):
        if isinstance(default, ast.Call) and ADMIN_RE.search(
            " ".join(_dotted(a) or "" for a in default.args)
        ):
            return True
    return False
