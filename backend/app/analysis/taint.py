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


def analyze_taint_project(sources: list[tuple[str, str]]) -> list[TaintFinding]:
    """Project-wide taint: intra/within-file per file plus cross-file flow from a handler
    into helper functions defined in other imported modules."""
    parsed: list[tuple[str, ast.AST, list[str], dict[str, ast.AST], dict[str, str]]] = []
    gfuncs: dict[str, list[tuple[ast.AST, str, list[str]]]] = {}
    imports_by_file: dict[str, dict[str, str]] = {}
    findings: list[TaintFinding] = []

    for relpath, text in sources:
        if relpath.endswith(JS_EXTENSIONS):
            findings += _js_taint(relpath, text)
            continue
        if not relpath.endswith(".py"):
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        lines = text.splitlines()
        funcs = {
            n.name: n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        imports = _collect_imports(tree)
        parsed.append((relpath, tree, lines, funcs, imports))
        imports_by_file[relpath] = imports
        for name, node in funcs.items():
            gfuncs.setdefault(name, []).append((node, relpath, lines))
        findings += _python_taint_tree(tree, relpath, lines, funcs)  # intra + within-file

    # Cross-file: from each handler, follow calls that resolve to other modules.
    for relpath, _tree, _lines, funcs, _imports in parsed:
        for func in funcs.values():
            if _is_handler(func):
                tainted = _function_tainted(func, _handler_param_taint(func))
                findings += _propagate_cross(
                    func, relpath, tainted, gfuncs, imports_by_file, 0, set()
                )

    unique: dict[tuple, TaintFinding] = {}
    for f in findings:
        unique[(f.relpath, f.line, f.vuln_type, f.sink)] = f
    return list(unique.values())


def _resolve_callee(call, caller_imports, gfuncs):
    name = _dotted(call.func) or ""
    simple = name.rsplit(".", 1)[-1]
    base = name.rsplit(".", 1)[0] if "." in name else None
    candidates = gfuncs.get(simple, [])
    if not candidates:
        return None
    hint = base or caller_imports.get(simple)
    if hint:
        want = hint.rsplit(".", 1)[-1]
        for node, rel, lines in candidates:
            stem = rel.rsplit("/", 1)[-1].removesuffix(".py")
            if stem == want:
                return node, rel, lines
    if len(candidates) == 1:
        return candidates[0]
    return None  # ambiguous name with no import hint: stay conservative


def _propagate_cross(func, relpath, tainted, gfuncs, imports_by_file, depth, visited):
    if depth >= MAX_CALL_DEPTH:
        return []
    caller_imports = imports_by_file.get(relpath, {})
    out: list[TaintFinding] = []
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        resolved = _resolve_callee(call, caller_imports, gfuncs)
        if resolved is None:
            continue
        callee, crel, clines = resolved
        passed = _tainted_params_for_call(call, tainted, callee)
        if not passed:
            continue
        key = (crel, getattr(callee, "name", ""), frozenset(passed))
        if key in visited:
            continue
        visited.add(key)
        ctaint = _function_tainted(callee, passed)
        out += _sinks_in_function(callee, ctaint, crel, clines)
        out += _propagate_cross(callee, crel, ctaint, gfuncs, imports_by_file, depth + 1, visited)
    return out


def _collect_imports(tree) -> dict[str, str]:
    """local name -> module string (for `from mod import name` and `import mod [as x]`)."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                imports[a.asname or a.name] = node.module
    return imports


# --------------------------------------------------------------------------- Python


def _python_taint(relpath: str, text: str) -> list[TaintFinding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    functions = {
        n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    findings = _python_taint_tree(tree, relpath, lines, functions)
    unique: dict[tuple, TaintFinding] = {}
    for f in findings:
        unique[(f.relpath, f.line, f.vuln_type, f.sink)] = f
    return list(unique.values())


def _python_taint_tree(tree, relpath: str, lines: list[str], functions: dict) -> list[TaintFinding]:
    """Intra + within-file interprocedural taint for one parsed module."""
    findings: list[TaintFinding] = []
    ctx = _Ctx(functions, 0, {})
    for func in functions.values():
        init = _handler_param_taint(func) if _is_handler(func) else set()
        tainted = _function_tainted(func, init, ctx)
        findings += _sinks_in_function(func, tainted, relpath, lines, ctx)
    for func in functions.values():
        if _is_handler(func):
            tainted = _function_tainted(func, _handler_param_taint(func), ctx)
            findings += _propagate(func, tainted, functions, relpath, lines, 0, set(), ctx)
    return findings


def _propagate(
    func, tainted, functions, relpath, lines, depth, visited, ctx: _Ctx | None = None
) -> list[TaintFinding]:
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
        passed = _tainted_params_for_call(call, tainted, callee, ctx)
        if not passed:
            continue
        key = (callee_name, frozenset(passed))
        if key in visited:
            continue
        visited.add(key)
        callee_tainted = _function_tainted(callee, passed, ctx)
        findings += _sinks_in_function(callee, callee_tainted, relpath, lines, ctx)
        findings += _propagate(
            callee, callee_tainted, functions, relpath, lines, depth + 1, visited, ctx
        )
    return findings


def _tainted_params_for_call(
    call: ast.Call, caller_tainted: set[str], callee, ctx: _Ctx | None = None
) -> set[str]:
    positional = [a.arg for a in [*getattr(callee.args, "posonlyargs", []), *callee.args.args]]
    passed: set[str] = set()
    for i, arg in enumerate(call.args):
        if i < len(positional) and _expr_tainted(arg, caller_tainted, ctx):
            passed.add(positional[i])
    names = set(positional) | {a.arg for a in callee.args.kwonlyargs}
    for kw in call.keywords:
        if kw.arg in names and _expr_tainted(kw.value, caller_tainted, ctx):
            passed.add(kw.arg)
    return passed


def _handler_param_taint(func) -> set[str]:
    injected = _injected_params(func)
    return {
        a.arg for a in _all_params(func) if a.arg not in SAFE_PARAM_NAMES and a.arg not in injected
    }


def _function_tainted(func, initial: set[str], ctx: _Ctx | None = None) -> set[str]:
    tainted = set(initial)
    assigns = _collect_assignments(func)
    changed = True
    while changed:
        changed = False
        for targets, value in assigns:
            if _expr_tainted(value, tainted, ctx):
                for t in targets:
                    if t not in tainted:
                        tainted.add(t)
                        changed = True
    return tainted


def _sinks_in_function(
    func, tainted: set[str], relpath: str, lines: list[str], ctx: _Ctx | None = None
) -> list[TaintFinding]:
    out: list[TaintFinding] = []
    seen: set[tuple[str, int]] = set()
    for call in ast.walk(func):
        if not isinstance(call, ast.Call):
            continue
        hit = _check_sink(call, tainted, ctx)
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


def _check_sink(
    call: ast.Call, tainted: set[str], ctx: _Ctx | None = None
) -> tuple[str, str] | None:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    args = call.args
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    a0 = args[0] if args else None

    if last in {"execute", "executemany", "executescript", "raw"} and _tainted(a0, tainted, ctx):
        return "sql_injection", name
    if last == "text" and _tainted(a0, tainted, ctx):
        return "sql_injection", name
    if (name in {"os.system", "os.popen"} or last in {"system", "popen", "getoutput"}) and any(
        _tainted(a, tainted, ctx) for a in args
    ):
        return "command_injection", name
    if (
        "subprocess" in name
        and _is_true(kw.get("shell"))
        and any(_tainted(a, tainted, ctx) for a in args)
    ):
        return "command_injection", f"{name}(shell=True)"
    if name in {"eval", "exec", "builtins.eval", "builtins.exec"} and _tainted(a0, tainted, ctx):
        return "code_injection", name
    if _is_http_call(name, last) and (
        _tainted(a0, tainted, ctx) or _tainted(kw.get("url"), tainted, ctx)
    ):
        return "ssrf", name
    if (
        name == "open" or last in {"send_file", "send_from_directory", "FileResponse"}
    ) and _tainted(a0, tainted, ctx):
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
        # Django REST Framework function view: @api_view([...]).
        if isinstance(f, ast.Name) and f.id == "api_view":
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


@dataclass
class _Ctx:
    """Return-value taint context: the file's functions, recursion depth, and a memo cache
    (pre-seeded False per key, which also breaks recursive call cycles)."""

    functions: dict
    depth: int = 0
    cache: dict | None = None


def _tainted(node: ast.expr | None, tainted: set[str], ctx: _Ctx | None = None) -> bool:
    return node is not None and _expr_tainted(node, tainted, ctx)


def _expr_tainted(node: ast.expr, tainted: set[str], ctx: _Ctx | None = None) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in tainted:
            return True
        if _is_source(sub):
            return True
        if (
            ctx is not None
            and isinstance(sub, ast.Call)
            and _call_returns_tainted(sub, tainted, ctx)
        ):
            return True
    return False


def _call_returns_tainted(call: ast.Call, tainted: set[str], ctx: _Ctx) -> bool:
    """True if a call to a function defined in this file returns attacker-influenced data,
    either derived from tainted arguments or read from request input inside the callee."""
    if ctx.depth >= MAX_CALL_DEPTH:
        return False
    callee = ctx.functions.get((_dotted(call.func) or "").rsplit(".", 1)[-1])
    if callee is None:
        return False
    passed = _tainted_params_for_call(call, tainted, callee, ctx)
    cache = ctx.cache if ctx.cache is not None else {}
    key = (id(callee), frozenset(passed))
    if key in cache:
        return cache[key]
    cache[key] = False  # in-progress guard: recursion resolves to False
    inner = _Ctx(ctx.functions, ctx.depth + 1, cache)
    callee_tainted = _function_tainted(callee, passed, inner)
    result = any(
        isinstance(n, ast.Return)
        and n.value is not None
        and _expr_tainted(n.value, callee_tainted, inner)
        for n in ast.walk(callee)
    )
    cache[key] = result
    return result


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
