"""Lightweight intraprocedural taint analysis: does untrusted request input reach a
dangerous sink within the same function?

This is what turns "a risky call exists somewhere" (sinks.py) into "user-controlled
data flows into this SQL query / command / outbound URL". Sources are web-request
inputs (handler parameters and ``request.*`` accesses); sinks are SQL execution,
command execution, code execution, outbound requests (SSRF) and filesystem paths.

It is intentionally lightweight and flow-insensitive within a function: it over-
approximates (may report a path a sanitizer actually neutralises), so findings are
"likely/suspicious", never "confirmed". Parameterised queries — where the SQL string
is constant and only the *parameters* are tainted — are correctly NOT flagged.
Python only; JS taint is future work.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from app.analysis.routes import HTTP_METHODS

SOURCE_ROOTS = {"request", "req"}
# Handler params that are framework-injected services, not raw user input.
SAFE_PARAM_NAMES = {"self", "cls", "db", "session", "request", "req", "current_user", "user"}

# vuln_type -> (cwe, owasp, remediation, strong)
# strong=True -> report status "likely"; else "suspicious".
TAINT_META = {
    "sql_injection": (
        "CWE-89",
        "A03:2021 Injection",
        "Use parameterised queries / bound parameters; never build SQL from input.",
        True,
    ),
    "command_injection": (
        "CWE-78",
        "A03:2021 Injection",
        "Avoid the shell; pass an argument list and validate input.",
        True,
    ),
    "code_injection": (
        "CWE-95",
        "A03:2021 Injection",
        "Never eval/exec untrusted input.",
        True,
    ),
    "ssrf": (
        "CWE-918",
        "A10:2021 Server-Side Request Forgery (SSRF)",
        "Validate/allowlist outbound URLs and block internal address ranges.",
        False,
    ),
    "path_traversal": (
        "CWE-22",
        "A01:2021 Broken Access Control",
        "Validate and normalise paths; restrict access to a base directory.",
        False,
    ),
}
SEVERITY = {
    "sql_injection": "high",
    "command_injection": "high",
    "code_injection": "critical",
    "ssrf": "high",
    "path_traversal": "high",
}


@dataclass(frozen=True)
class TaintFinding:
    vuln_type: str
    severity: str
    confidence: float
    relpath: str
    line: int
    sink: str
    evidence: str

    @property
    def cwe(self) -> str:
        return TAINT_META[self.vuln_type][0]

    @property
    def owasp(self) -> str:
        return TAINT_META[self.vuln_type][1]

    @property
    def remediation(self) -> str:
        return TAINT_META[self.vuln_type][2]

    @property
    def strong(self) -> bool:
        return TAINT_META[self.vuln_type][3]

    @property
    def title(self) -> str:
        return f"{self.vuln_type.replace('_', ' ').title()} (tainted input → {self.sink})"


def analyze_taint(relpath: str, text: str) -> list[TaintFinding]:
    if not relpath.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    findings: list[TaintFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _analyze_function(node, relpath, lines, findings)
    return findings


def _analyze_function(func, relpath: str, lines: list[str], out: list[TaintFinding]) -> None:
    tainted: set[str] = set()
    if _is_handler(func):
        injected = _injected_params(func)
        for arg in _all_params(func):
            if arg.arg not in SAFE_PARAM_NAMES and arg.arg not in injected:
                tainted.add(arg.arg)

    assigns = _collect_assignments(func)
    changed = True
    while changed:  # fixpoint: propagate taint through assignments
        changed = False
        for targets, value in assigns:
            if _expr_tainted(value, tainted):
                for t in targets:
                    if t not in tainted:
                        tainted.add(t)
                        changed = True

    seen: set[tuple[str, int]] = set()
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        hit = _check_sink(call, tainted)
        if hit and (hit[0], call.lineno) not in seen:
            seen.add((hit[0], call.lineno))
            vuln_type, sink = hit
            snippet = lines[call.lineno - 1].strip()[:160] if 0 < call.lineno <= len(lines) else ""
            out.append(
                TaintFinding(
                    vuln_type=vuln_type,
                    severity=SEVERITY[vuln_type],
                    confidence=0.75,
                    relpath=relpath,
                    line=call.lineno,
                    sink=sink,
                    evidence=snippet,
                )
            )


def _check_sink(call: ast.Call, tainted: set[str]) -> tuple[str, str] | None:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    args = call.args
    kw = {k.arg: k.value for k in call.keywords if k.arg}

    def arg0() -> ast.expr | None:
        return args[0] if args else None

    # SQL: the *query* argument tainted (parameters passed separately stay safe).
    if last in {"execute", "executemany", "executescript", "raw"} and _tainted(arg0(), tainted):
        return "sql_injection", name
    if last == "text" and _tainted(arg0(), tainted):
        # sqlalchemy.text(tainted) builds raw SQL from input.
        return "sql_injection", name

    # Command execution
    if (name in {"os.system", "os.popen"} or last in {"system", "popen", "getoutput"}) and any(
        _tainted(a, tainted) for a in args
    ):
        return "command_injection", name
    if (
        "subprocess" in name
        and _is_true(kw.get("shell"))
        and any(_tainted(a, tainted) for a in args)
    ):
        return "command_injection", f"{name}(shell=True)"

    # Code execution
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and _tainted(arg0(), tainted):
        return "code_injection", name

    # SSRF: outbound HTTP with a tainted URL.
    if _is_http_call(name, last) and (
        _tainted(arg0(), tainted) or _tainted(kw.get("url"), tainted)
    ):
        return "ssrf", name

    # Path traversal: filesystem path built from input.
    if (
        name == "open" or last in {"send_file", "send_from_directory", "FileResponse"}
    ) and _tainted(arg0(), tainted):
        return "path_traversal", name

    return None


def _is_http_call(name: str, last: str) -> bool:
    if last == "urlopen" or name.endswith("urlopen"):
        return True
    if last not in {"get", "post", "put", "delete", "patch", "head", "request", "Request"}:
        return False
    return any(m in name.lower() for m in ("requests", "httpx", "aiohttp", "session", "urllib"))


# --------------------------------------------------------------------------- helpers


def _all_params(func):
    a = func.args
    return [*getattr(a, "posonlyargs", []), *a.args, *a.kwonlyargs]


def _injected_params(func) -> set[str]:
    names: set[str] = set()
    a = func.args
    positional = [*getattr(a, "posonlyargs", []), *a.args]
    for arg, default in zip(
        positional[len(positional) - len(a.defaults) :], a.defaults, strict=False
    ):
        if _is_depends(default):
            names.add(arg.arg)
    for arg, default in zip(a.kwonlyargs, a.kw_defaults, strict=False):
        if default is not None and _is_depends(default):
            names.add(arg.arg)
    return names


def _is_depends(node) -> bool:
    return isinstance(node, ast.Call) and (_dotted(node.func) or "").rsplit(".", 1)[-1] in {
        "Depends",
        "Security",
    }


def _is_handler(func) -> bool:
    for dec in func.decorator_list:
        f = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(f, ast.Attribute) and f.attr.lower() in HTTP_METHODS | {"route"}:
            return True
    return False


def _collect_assignments(func) -> list[tuple[list[str], ast.expr]]:
    out: list[tuple[list[str], ast.expr]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            out.append((_target_names(node.targets), node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            out.append((_target_names([node.target]), node.value))
        elif isinstance(node, ast.AugAssign):
            out.append((_target_names([node.target]), node.value))
        elif isinstance(node, ast.NamedExpr):
            out.append((_target_names([node.target]), node.value))
    return out


def _target_names(targets) -> list[str]:
    names: list[str] = []
    for t in targets:
        for sub in ast.walk(t):
            if isinstance(sub, ast.Name):
                names.append(sub.id)
    return names


def _tainted(node: ast.expr | None, tainted: set[str]) -> bool:
    return node is not None and _expr_tainted(node, tainted)


def _expr_tainted(node: ast.expr, tainted: set[str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        if _is_source(sub):
            return True
    return False


def _is_source(node: ast.expr) -> bool:
    return (
        isinstance(node, (ast.Attribute, ast.Subscript, ast.Call))
        and _root_name(node) in SOURCE_ROOTS
    )


def _root_name(node: ast.expr) -> str | None:
    while True:
        if isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, (ast.Attribute, ast.Subscript)):
            node = node.value
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
