"""Business-logic detectors: the server trusting values the client controls (ADR-010).

Three Python-AST rules over request handlers:
- **mass assignment** (CWE-915): request data expanded straight into a model/update call;
- **client-trusted privilege** (CWE-269): ``role`` / ``is_admin`` ... set from request data;
- **client-trusted value** (CWE-602): ``price`` / ``amount`` ... taken from the client.

Taint here is deliberately narrow: only values that trace back to a ``request.*`` source count.
Path parameters and validated schema bodies are not treated as attacker-shaped, which keeps
false positives low. Findings are heuristic ("suspicious"); a serializer or middleware outside
the handler can neutralise the pattern.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.analysis.taint import _dotted, _is_handler, _is_source, mark_view_handlers

PRIVILEGE_FIELDS = {
    "role",
    "roles",
    "is_admin",
    "is_staff",
    "is_superuser",
    "admin",
    "permissions",
    "is_verified",
    "email_verified",
}
VALUE_FIELDS = {
    "price",
    "unit_price",
    "amount",
    "total",
    "subtotal",
    "discount",
    "cost",
    "fee",
    "balance",
    "credits",
}

CATEGORY = {
    "mass_assignment": (
        "CWE-915",
        "A04:2021 Insecure Design",
        "Copy only an explicit allow-list of fields from request data; never expand the whole "
        "request body into a model or update call.",
        "high",
        0.55,
    ),
    "client_trusted_privilege": (
        "CWE-269",
        "A01:2021 Broken Access Control",
        "Never take roles or privilege flags from the request; derive them server-side from the "
        "authenticated identity and an administrative workflow.",
        "high",
        0.65,
    ),
    "client_trusted_value": (
        "CWE-602",
        "A04:2021 Insecure Design",
        "Look up prices, totals and balances server-side from trusted data; treat any "
        "client-supplied value as a hint to validate, not a source of truth.",
        "high",
        0.55,
    ),
    "inconsistent_authorization": (
        "CWE-862",
        "A01:2021 Broken Access Control",
        "Apply the same authorization guard as the sibling routes, or document why this route is "
        "intentionally public.",
        "high",
        0.6,
    ),
    "intent_violation": (
        "CWE-862",
        "A01:2021 Broken Access Control",
        "Bring the code in line with the declared rule, or correct the rule if the intent changed.",
        "high",
        0.7,
    ),
}

_MODEL_CALL = re.compile(r"^[A-Z]")  # Order(**data), User(**data)
_UPDATE_METHODS = {"update", "create", "update_or_create", "bulk_create", "set"}


@dataclass(frozen=True)
class LogicFinding:
    category: str
    rule: str
    severity: str
    confidence: float
    relpath: str
    line: int
    handler: str
    field: str
    evidence: str
    cwe_override: str | None = None  # set by intent rules that map to a different CWE

    @property
    def cwe(self) -> str:
        return self.cwe_override or CATEGORY[self.category][0]

    @property
    def owasp(self) -> str:
        return CATEGORY[self.category][1]

    @property
    def remediation(self) -> str:
        return CATEGORY[self.category][2]

    @property
    def title(self) -> str:
        if self.category == "intent_violation":
            return f"Declared rule violated: {self.rule}"
        if self.category == "inconsistent_authorization":
            return f"Inconsistent authorization: {self.rule}"
        return f"Business-logic flaw in {self.handler}(): {self.rule}"


def analyze_business_logic(
    relpath: str, text: str, extra_fields: frozenset[str] = frozenset()
) -> list[LogicFinding]:
    if not relpath.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    mark_view_handlers(tree)
    lines = text.splitlines()
    privileged = PRIVILEGE_FIELDS | extra_fields
    out: list[LogicFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_handler(node):
            _analyze_handler(node, relpath, lines, privileged, out)
    return out


def _analyze_handler(func, relpath, lines, privileged, out) -> None:
    client = _client_names(func)
    seen: set[tuple[int, str]] = set()

    def add(category: str, rule: str, line: int, field: str) -> None:
        if (line, category) in seen:
            return
        seen.add((line, category))
        sev, conf = CATEGORY[category][3], CATEGORY[category][4]
        evidence = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        out.append(
            LogicFinding(category, rule, sev, conf, relpath, line, func.name, field, evidence)
        )

    def from_client(node) -> bool:
        return node is not None and _from_client(node, client)

    def classify_field(name: str, line: int) -> bool:
        key = name.lower()
        if key in privileged:
            add("client_trusted_privilege", f"'{name}' is set from request data", line, name)
            return True
        if key in VALUE_FIELDS:
            add("client_trusted_value", f"'{name}' is taken from the client", line, name)
            return True
        return False

    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg is None:  # **expansion
                    if from_client(kw.value) and _is_model_or_update(node):
                        add(
                            "mass_assignment",
                            "request data expanded directly into a model/update call",
                            node.lineno,
                            "**",
                        )
                elif from_client(kw.value):
                    classify_field(kw.arg, node.lineno)
            if _is_setattr_from_client(node, client):
                add("mass_assignment", "setattr() driven by request keys", node.lineno, "setattr")
        elif isinstance(node, ast.Assign):
            if not from_client(node.value):
                continue
            for target in node.targets:
                name = _target_name(target)
                if name:
                    classify_field(name, node.lineno)


def _client_names(func) -> set[str]:
    """Names assigned (transitively) from a request source. Parameters are excluded."""
    names: set[str] = set()
    binders = [
        n
        for n in ast.walk(func)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.For, ast.AsyncFor))
    ]
    changed = True
    while changed:
        changed = False
        for b in binders:
            if isinstance(b, (ast.For, ast.AsyncFor)):
                value, targets = b.iter, [b.target]
            else:
                value = b.value
                targets = b.targets if isinstance(b, ast.Assign) else [b.target]
            if value is None or not _from_client(value, names):
                continue
            for t in targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name) and sub.id not in names:
                        names.add(sub.id)
                        changed = True
    return names


# Calls that merely convert/combine their arguments keep the value client-controlled.
_PASSTHROUGH = {
    "int", "float", "str", "bool", "Decimal", "abs", "round", "max", "min", "dict", "list",
    "tuple", "set", "sorted", "strip", "lower", "upper",
}  # fmt: skip


def _from_client(node, names: set[str]) -> bool:
    """True if the expression's value is (derived from) data the client controls.

    A lookup keyed by a client value (``Product.query.get(request.json["id"])``) returns
    server-owned data, so arbitrary calls end the taint; only conversions and methods on
    client data (``float(x)``, ``data.get("k")``) carry it.
    """
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)) and _is_source(node):
        return True
    if isinstance(node, ast.Subscript):
        return _from_client(node.value, names)  # CATALOG[client_key] is server data
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and _from_client(fn.value, names):
            return True  # method on client data: data.get("price")
        name = (_dotted(fn) or "").rsplit(".", 1)[-1]
        if name in _PASSTHROUGH:
            return any(
                _from_client(a, names) for a in [*node.args, *(k.value for k in node.keywords)]
            )
        return False
    return any(
        _from_client(child, names)
        for child in ast.iter_child_nodes(node)
        if isinstance(child, ast.expr)
    )


def _is_model_or_update(call: ast.Call) -> bool:
    name = (_dotted(call.func) or "").rsplit(".", 1)[-1]
    if _MODEL_CALL.match(name):
        return True
    return name in _UPDATE_METHODS


def _is_setattr_from_client(call: ast.Call, client: set[str]) -> bool:
    return (
        isinstance(call.func, ast.Name)
        and call.func.id == "setattr"
        and len(call.args) >= 2
        and _from_client(call.args[1], client)
    )


def _target_name(target) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
        value = target.slice.value
        return value if isinstance(value, str) else None
    return None
