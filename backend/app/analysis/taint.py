"""Taint analysis: does untrusted request input reach a dangerous sink?

Python analysis is AST-based and now **interprocedural within a file**: taint flows
from a handler into locally-defined functions it calls (bounded depth, cycle-guarded),
so an injection reached through a helper is caught, not only an inline one. It stays
flow-insensitive within each function and does not cross files or model sanitizers, so
findings are "likely/suspicious", never "confirmed". Parameterised queries (constant
SQL, tainted parameters only) are not flagged.

JavaScript/TypeScript analysis is a lighter, file-scoped heuristic over ``req.*``
sources. Both are honest about their limits via finding status and confidence.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.analysis.routes import HTTP_METHODS

SOURCE_ROOTS = {"request", "req"}
SAFE_PARAM_NAMES = {"self", "cls", "db", "session", "request", "req", "current_user", "user"}
MAX_CALL_DEPTH = 4

# vuln_type -> (cwe, owasp, remediation, strong)  strong=True -> status likely else suspicious
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
    "open_redirect": (
        "CWE-601",
        "A01:2021 Broken Access Control",
        "Allowlist redirect targets; do not redirect to a raw user-supplied URL.",
        False,
    ),
}
SEVERITY = {
    "sql_injection": "high",
    "command_injection": "high",
    "code_injection": "critical",
    "ssrf": "high",
    "path_traversal": "high",
    "open_redirect": "medium",
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


JS_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def analyze_taint(relpath: str, text: str) -> list[TaintFinding]:
    if relpath.endswith(".py"):
        return _python_taint(relpath, text)
    if relpath.endswith(JS_EXTENSIONS):
        return _js_taint(relpath, text)
    return []


# --------------------------------------------------------------------------- Python


def _python_taint(relpath: str, text: str) -> list[TaintFinding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    functions: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node

    findings: list[TaintFinding] = []
    # Intraprocedural: every function; handlers seed their params as sources.
    for func in functions.values():
        init = _handler_param_taint(func) if _is_handler(func) else set()
        tainted = _function_tainted(func, init)
        findings += _sinks_in_function(func, tainted, relpath, lines)
    # Interprocedural: follow taint from each handler into local callees.
    for func in functions.values():
        if _is_handler(func):
            tainted = _function_tainted(func, _handler_param_taint(func))
            findings += _propagate(func, tainted, functions, relpath, lines, 0, set())

    # Deduplicate (a helper reachable from several handlers, or intra+inter overlap).
    unique: dict[tuple, TaintFinding] = {}
    for f in findings:
        unique[(f.relpath, f.line, f.vuln_type, f.sink)] = f
    return list(unique.values())


def _propagate(func, tainted, functions, relpath, lines, depth, visited) -> list[TaintFinding]:
    if depth >= MAX_CALL_DEPTH:
        return []
    findings: list[TaintFinding] = []
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        callee_name = (_dotted(call.func) or "").rsplit(".", 1)[-1]
        callee = functions.get(callee_name)
        if callee is None:
            continue
        passed = _tainted_params_for_call(call, tainted, callee)
        if not passed:
            continue
        key = (callee_name, frozenset(passed))
        if key in visited:
            continue
        visited.add(key)
        callee_tainted = _function_tainted(callee, passed)
        findings += _sinks_in_function(callee, callee_tainted, relpath, lines)
        findings += _propagate(
            callee, callee_tainted, functions, relpath, lines, depth + 1, visited
        )
    return findings


def _tainted_params_for_call(call: ast.Call, caller_tainted: set[str], callee) -> set[str]:
    positional = [a.arg for a in [*getattr(callee.args, "posonlyargs", []), *callee.args.args]]
    passed: set[str] = set()
    for i, arg in enumerate(call.args):
        if i < len(positional) and _expr_tainted(arg, caller_tainted):
            passed.add(positional[i])
    names = set(positional) | {a.arg for a in callee.args.kwonlyargs}
    for kw in call.keywords:
        if kw.arg in names and _expr_tainted(kw.value, caller_tainted):
            passed.add(kw.arg)
    return passed


def _handler_param_taint(func) -> set[str]:
    injected = _injected_params(func)
    return {
        a.arg for a in _all_params(func) if a.arg not in SAFE_PARAM_NAMES and a.arg not in injected
    }


def _function_tainted(func, initial: set[str]) -> set[str]:
    tainted = set(initial)
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


def _sinks_in_function(
    func, tainted: set[str], relpath: str, lines: list[str]
) -> list[TaintFinding]:
    out: list[TaintFinding] = []
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
                    vuln_type, SEVERITY[vuln_type], 0.75, relpath, call.lineno, sink, snippet
                )
            )
    return out


def _check_sink(call: ast.Call, tainted: set[str]) -> tuple[str, str] | None:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    args = call.args
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    a0 = args[0] if args else None

    if last in {"execute", "executemany", "executescript", "raw"} and _tainted(a0, tainted):
        return "sql_injection", name
    if last == "text" and _tainted(a0, tainted):
        return "sql_injection", name
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
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and _tainted(a0, tainted):
        return "code_injection", name
    if _is_http_call(name, last) and (_tainted(a0, tainted) or _tainted(kw.get("url"), tainted)):
        return "ssrf", name
    if (
        name == "open" or last in {"send_file", "send_from_directory", "FileResponse"}
    ) and _tainted(a0, tainted):
        return "path_traversal", name
    return None


def _is_http_call(name: str, last: str) -> bool:
    if last == "urlopen" or name.endswith("urlopen"):
        return True
    if last not in {"get", "post", "put", "delete", "patch", "head", "request", "Request"}:
        return False
    return any(m in name.lower() for m in ("requests", "httpx", "aiohttp", "session", "urllib"))


# --------------------------------------------------------------------------- JS / TS

_JS_SOURCE = re.compile(r"\breq(?:uest)?\.(?:query|params|body|cookies|headers)\b")
_JS_ASSIGN = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*=\s*[^;]*req(?:uest)?\.(?:query|params|body|cookies|headers)"
)
_JS_DESTRUCTURE = re.compile(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\.(?:query|params|body|cookies|headers)"
)
_JS_SINKS = [
    ("sql_injection", re.compile(r"\.(query|execute)\s*\("), re.compile(r"[`+]|\$\{")),
    ("command_injection", re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\("), None),
    ("code_injection", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("), None),
    ("ssrf", re.compile(r"\b(?:axios|fetch)\s*\(|\bhttps?\.(?:get|request)\s*\("), None),
    (
        "path_traversal",
        re.compile(
            r"\bfs\.(?:readFile|readFileSync|createReadStream|writeFile)\s*\(|\.sendFile\s*\("
        ),
        None,
    ),
    ("open_redirect", re.compile(r"\.redirect\s*\("), None),
]


def _js_taint(relpath: str, text: str) -> list[TaintFinding]:
    lines = text.splitlines()
    tainted: set[str] = set()
    for line in lines:
        for m in _JS_ASSIGN.finditer(line):
            tainted.add(m.group(1))
        for m in _JS_DESTRUCTURE.finditer(line):
            tainted.update(re.findall(r"\w+", m.group(1)))

    var_res = [re.compile(r"\b" + re.escape(v) + r"\b") for v in tainted]
    findings: list[TaintFinding] = []
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(lines, start=1):
        if len(line) > 4000:
            continue
        if not (_JS_SOURCE.search(line) or any(r.search(line) for r in var_res)):
            continue
        for vuln_type, sink_re, extra_re in _JS_SINKS:
            m = sink_re.search(line)
            if (
                m
                and (extra_re is None or extra_re.search(line))
                and (vuln_type, lineno) not in seen
            ):
                seen.add((vuln_type, lineno))
                findings.append(
                    TaintFinding(
                        vuln_type,
                        SEVERITY[vuln_type],
                        0.6,
                        relpath,
                        lineno,
                        m.group(0).strip("( "),
                        line.strip()[:160],
                    )
                )
    return findings


# --------------------------------------------------------------------------- shared helpers


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
