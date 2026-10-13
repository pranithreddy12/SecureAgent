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

from app.analysis import extra_detectors as xd
from app.analysis.routes import _CBV_BASE_HINTS, _CBV_METHOD_MAP, HTTP_METHODS

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
    "template_injection": (
        "CWE-1336",
        "A03:2021 Injection",
        "Never build a template from input; pass input as template variables and render a fixed "
        "template.",
        False,
    ),
    "xpath_injection": (
        "CWE-643",
        "A03:2021 Injection",
        "Use parameterised XPath (variables) instead of formatting input into the expression.",
        False,
    ),
    "nosql_injection": (
        "CWE-943",
        "A03:2021 Injection",
        "Do not pass request objects as query filters or build $where strings; validate types and "
        "use fixed operators.",
        False,
    ),
    "reflected_xss": (
        "CWE-79",
        "A03:2021 Injection",
        "Escape input before placing it in HTML (or render with an auto-escaping template).",
        False,
    ),
    "idor": (
        "CWE-639",
        "A01:2021 Broken Access Control",
        "Scope the lookup to the authenticated user (owner / tenant) as well as the id.",
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
    "template_injection": "high",
    "xpath_injection": "high",
    "nosql_injection": "high",
    "reflected_xss": "medium",
    "idor": "high",
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
    path: tuple[str, ...] = ()  # source -> ... -> sink, one human-readable step each

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
        mark_view_handlers(tree)
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

    # Cross-file: from each handler, follow calls that resolve to other modules. Each file keeps
    # its own return-value context so a helper's same-file callees are judged by their bodies.
    ctxs = {rel: _Ctx(funcs, 0, {}) for rel, _t, _l, funcs, _i in parsed}
    for relpath, ptree, _lines, _funcs, _imports in parsed:
        for func in _all_function_nodes(ptree):
            if _is_handler(func):
                tainted = _function_tainted(func, _handler_param_taint(func), ctxs.get(relpath))
                findings += _propagate_cross(
                    func, relpath, tainted, gfuncs, imports_by_file, 0, set(), ctxs
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


def _propagate_cross(func, relpath, tainted, gfuncs, imports_by_file, depth, visited, ctxs=None):
    ctxs = ctxs or {}
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
        cctx = ctxs.get(crel)
        passed = _tainted_params_for_call(call, tainted, callee, ctxs.get(relpath))
        if not passed:
            continue
        key = (crel, getattr(callee, "name", ""), frozenset(passed))
        if key in visited:
            continue
        visited.add(key)
        ctaint = _function_tainted(
            callee, passed, cctx, _call_origins(call, callee, tainted, relpath, passed)
        )
        out += _sinks_in_function(callee, ctaint, crel, clines, cctx)
        out += _propagate_cross(
            callee, crel, ctaint, gfuncs, imports_by_file, depth + 1, visited, ctxs
        )
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
    mark_view_handlers(tree)
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
    all_funcs = _all_function_nodes(tree)
    for func in all_funcs:
        init = _handler_param_taint(func) if _is_handler(func) else set()
        tainted = _function_tainted(func, init, ctx)
        findings += _sinks_in_function(func, tainted, relpath, lines, ctx)
    for func in all_funcs:
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
        callee_tainted = _function_tainted(
            callee, passed, ctx, _call_origins(call, callee, tainted, relpath, passed)
        )
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


def _allowlist_guarded(func) -> set[str]:
    """Names validated by an early-exit allow-list check::

        if host not in ALLOWED:        # also: assert host in ALLOWED
            return / raise / abort(...)

    After such a check the value is one of the allowed ones, so it is not attacker-shaped. The
    check is position-insensitive (a use *before* the guard is not distinguished)."""
    guarded: set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.If) and _membership_name(node.test, negated=True):
            name = _membership_name(node.test, negated=True)
            if _exits(node.body) or _resets_to_default(node.body, name, func):
                guarded.add(name)
        elif isinstance(node, ast.Assert) and _membership_name(node.test, negated=False):
            guarded.add(_membership_name(node.test, negated=False))
    return guarded


def _resets_to_default(body: list[ast.stmt], name: str, func) -> bool:
    """``if col not in ALLOWED: col = "name"`` -- the invalid value is replaced by a constant (or
    by a parameter whose default is a constant), so afterwards ``col`` is always an allowed one."""
    const_defaults: set[str] = set()
    args = func.args
    positional = [*args.posonlyargs, *args.args]
    for a, d in zip(reversed(positional), reversed(args.defaults), strict=False):
        if isinstance(d, ast.Constant):
            const_defaults.add(a.arg)
    for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True):
        if isinstance(d, ast.Constant):
            const_defaults.add(a.arg)
    for stmt in body:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and stmt.targets[0].id == name
            and (
                isinstance(stmt.value, ast.Constant)
                or (isinstance(stmt.value, ast.Name) and stmt.value.id in const_defaults)
            )
        ):
            return True
    return False


def _membership_name(test, *, negated: bool) -> str | None:
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.left, ast.Name)
        and isinstance(test.ops[0], ast.NotIn if negated else ast.In)
        and isinstance(
            test.comparators[0],
            (ast.Name, ast.Attribute, ast.Subscript, ast.Set, ast.List, ast.Tuple),
        )
    ):
        return test.left.id
    return None


def _exits(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return (_dotted(last.value.func) or "").rsplit(".", 1)[-1] in {"abort", "exit", "fail"}
    return False


class _TaintSet(set):
    """A set of tainted names that also remembers *why* each became tainted (for explanations).

    ``origins`` maps an initially-tainted name (a parameter) to the steps that led to it;
    ``parents`` maps a derived name to the (line, value expression) that tainted it."""

    origins: dict[str, list[str]]
    parents: dict[str, tuple[int, ast.expr]]
    orm_names: set[str] = frozenset()  # type: ignore[assignment]


def _function_tainted(
    func,
    initial: set[str],
    ctx: _Ctx | None = None,
    origins: dict[str, list[str]] | None = None,
) -> _TaintSet:
    guarded = _allowlist_guarded(func)
    tainted = _TaintSet(set(initial) - guarded)
    tainted.parents = {}
    tainted.orm_names = _orm_statement_names(func)
    if origins is None:  # entry point: its parameters are the request input
        origins = {n: [f"handler parameter `{n}` (request input)"] for n in initial}
    tainted.origins = origins
    assigns = _collect_assignments_lined(func)
    changed = True
    while changed:
        changed = False
        for targets, value, lineno in assigns:
            if _expr_tainted(value, tainted, ctx):
                for t in targets:
                    if t not in tainted and t not in guarded and t not in tainted.orm_names:
                        tainted.add(t)
                        tainted.parents[t] = (lineno, value)
                        changed = True
    return tainted


def _collect_assignments_lined(func) -> list[tuple[list[str], ast.expr, int]]:
    out: list[tuple[list[str], ast.expr, int]] = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            out.append((_target_names(node.targets), node.value, node.lineno))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            out.append((_target_names([node.target]), node.value, node.lineno))
        elif isinstance(node, (ast.AugAssign, ast.NamedExpr)):
            out.append((_target_names([node.target]), node.value, node.lineno))
    return out


def _short(node: ast.AST, limit: int = 90) -> str:
    try:
        text = " ".join(ast.unparse(node).split())
    except Exception:  # noqa: BLE001 - explanation text must never break analysis
        return "<expression>"
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _trace_expr(expr, tainted, relpath: str, ctx: _Ctx | None = None) -> list[str]:
    """Steps (source first) explaining why ``expr`` is attacker-influenced."""
    steps: list[str] = []
    seen: set[str] = set()

    def from_expr(e) -> None:
        for sub in _iter_unsanitized(e):
            if isinstance(sub, ast.Name) and sub.id in tainted:
                from_name(sub.id)
                return
            if (
                ctx is not None
                and isinstance(sub, ast.Call)
                and not _is_source(sub)
                and _call_returns_tainted(sub, tainted, ctx)
            ):
                steps.append(
                    f"{relpath}:{sub.lineno}  {_short(sub)}  (returns request-controlled data)"
                )
                return
            if _is_source(sub):
                steps.append(
                    f"{relpath}:{getattr(sub, 'lineno', '?')}  {_short(sub)}  (request input)"
                )
                return

    def from_name(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        parents = getattr(tainted, "parents", {})
        origins = getattr(tainted, "origins", {})
        if name in parents:
            lineno, value = parents[name]
            if _is_source(value):  # `q = request.args.get("q")`: one step, not two
                steps.append(f"{relpath}:{lineno}  {name} = {_short(value)}  (request input)")
                return
            from_expr(value)
            steps.append(f"{relpath}:{lineno}  {name} = {_short(value)}")
        elif name in origins:
            steps.extend(origins[name])
        else:
            steps.append(f"{relpath}  `{name}` (tainted parameter)")

    from_expr(expr)
    return steps


def _call_origins(call: ast.Call, callee, caller_tainted, relpath: str, passed) -> dict:
    """For each tainted parameter of ``callee``: the caller-side steps plus the hop itself."""
    positional = [a.arg for a in [*getattr(callee.args, "posonlyargs", []), *callee.args.args]]
    pairs = list(zip(positional, call.args, strict=False))
    pairs += [(kw.arg, kw.value) for kw in call.keywords if kw.arg]
    out: dict[str, list[str]] = {}
    for pname, arg in pairs:
        if pname in passed:
            steps = _trace_expr(arg, caller_tainted, relpath)
            steps.append(
                f"{relpath}:{call.lineno}  passed to {getattr(callee, 'name', '?')}() as `{pname}`"
            )
            out[pname] = steps
    return out


def _sinks_in_function(
    func, tainted: set[str], relpath: str, lines: list[str], ctx: _Ctx | None = None
) -> list[TaintFinding]:
    out: list[TaintFinding] = []
    seen: set[tuple[str, int]] = set()
    handler = _is_handler(func)
    for call in ast.walk(func):
        if (
            handler
            and isinstance(call, ast.Return)
            and xd.return_xss(call, lambda n: n is not None and _tainted(n, tainted, ctx))
        ):
            out.append(
                TaintFinding(
                    "reflected_xss",
                    SEVERITY["reflected_xss"],
                    0.6,
                    relpath,
                    call.lineno,
                    "return",
                    lines[call.lineno - 1].strip()[:160] if 0 < call.lineno <= len(lines) else "",
                )
            )
            continue
        if not isinstance(call, ast.Call):
            continue
        hit = _check_sink(call, tainted, ctx)
        if hit and (hit[0], call.lineno) not in seen:
            seen.add((hit[0], call.lineno))
            vuln_type, sink = hit
            snippet = lines[call.lineno - 1].strip()[:160] if 0 < call.lineno <= len(lines) else ""
            severity, confidence = SEVERITY[vuln_type], 0.75
            if vuln_type == "sql_injection" and _is_query_param_passthrough(func, call):
                # A generic DB wrapper `def run(query, *args): conn.execute(query, *args)`: the
                # query text is built by the *callers*, which is where the review belongs.
                severity, confidence = "medium", 0.35
                snippet = f"{snippet}  [query text arrives from callers via a parameter]"
            out.append(
                TaintFinding(
                    vuln_type,
                    severity,
                    confidence,
                    relpath,
                    call.lineno,
                    sink,
                    snippet,
                    _sink_path(call, tainted, relpath, sink, ctx),
                )
            )
    return out


def _sink_path(
    call: ast.Call, tainted, relpath: str, sink: str, ctx: _Ctx | None = None
) -> tuple[str, ...]:
    steps: list[str] = []
    for arg in [*call.args, *(k.value for k in call.keywords)]:
        if _expr_tainted(arg, tainted, ctx):
            steps = _trace_expr(arg, tainted, relpath, ctx)
            break
    steps.append(f"{relpath}:{call.lineno}  {sink}(…)  (sink)")
    return tuple(steps[-8:])  # long chains: keep the part nearest the sink


def _check_sink(
    call: ast.Call, tainted: set[str], ctx: _Ctx | None = None
) -> tuple[str, str] | None:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    args = call.args
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    a0 = args[0] if args else None

    if (
        last in {"execute", "executemany", "executescript", "raw"}
        and _tainted(a0, tainted, ctx)
        and not _is_parameterised_orm_expr(a0, tainted, ctx)
    ):
        return "sql_injection", name
    if last == "text" and _tainted(a0, tainted, ctx):
        return "sql_injection", name
    if (
        last == "send_header"
        and len(args) >= 2
        and isinstance(a0, ast.Constant)
        and isinstance(a0.value, str)
        and a0.value.lower() == "location"
        and _tainted(args[1], tainted, ctx)
    ):
        return "open_redirect", name
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
    if (
        last
        in {"redirect", "RedirectResponse", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}
        and a0 is not None
        and not (isinstance(a0, ast.Call) and (_dotted(a0.func) or "").endswith("url_for"))
        and _tainted(a0, tainted, ctx)
    ):
        return "open_redirect", name
    if _is_http_call(name, last) and (
        _tainted(_url_part(a0), tainted, ctx) or _tainted(kw.get("url"), tainted, ctx)
    ):
        return "ssrf", name
    if (
        name == "open" or last in {"send_file", "send_from_directory", "FileResponse"}
    ) and _tainted(a0, tainted, ctx):
        return "path_traversal", name
    return xd.taint_sink(call, lambda n: n is not None and _tainted(n, tainted, ctx))


_ORM_ROOTS = {"select", "insert", "update", "delete", "exists", "union", "union_all"}
_RAW_SQL_BUILDERS = {"text", "literal_column", "literal"}


def _orm_statement_names(func) -> set[str]:
    """Variables that only ever hold a SQLAlchemy statement built from ``select(...)`` & co.

    ``stmt = select(X).where(...)`` then ``stmt = stmt.where(X.a == v)``: the values are bound
    parameters, so the statement object is not tainted by what is passed into ``.where()``."""
    assigns: dict[str, list[ast.expr]] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assigns.setdefault(t.id, []).append(node.value)
    names = set(assigns)  # greatest fixpoint: `stmt = stmt.where(...)` refers to itself
    changed = True
    while changed:
        changed = False
        for name in list(names):
            if not all(_is_orm_chain(v, names) for v in assigns[name]):
                names.discard(name)
                changed = True
    return names


def _is_orm_chain(node: ast.expr, known: set[str]) -> bool:
    root = node
    while isinstance(root, (ast.Call, ast.Attribute)):
        root = root.func if isinstance(root, ast.Call) else root.value
    if not (isinstance(root, ast.Name) and (root.id in _ORM_ROOTS or root.id in known)):
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and (_dotted(sub.func) or "").rsplit(".", 1)[-1] in (
            _RAW_SQL_BUILDERS
        ):
            return False  # text(f"...") keeps the finding
    return True


def _is_parameterised_orm_expr(node, tainted: set[str], ctx: _Ctx | None) -> bool:
    """``select(...).where(col == value)``: SQLAlchemy binds ``value`` as a parameter, so a
    tainted value inside it is not SQL injection. Raw-SQL builders nested inside (``text(f"..")``)
    keep the finding."""
    root = node
    while isinstance(root, ast.Call) or isinstance(root, ast.Attribute):
        root = root.func if isinstance(root, ast.Call) else root.value
    orm_names = getattr(tainted, "orm_names", ())
    if not (isinstance(root, ast.Name) and (root.id in _ORM_ROOTS or root.id in orm_names)):
        return False
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and (_dotted(sub.func) or "").rsplit(".", 1)[-1] in _RAW_SQL_BUILDERS
            and any(_tainted(a, tainted, ctx) for a in sub.args)
        ):
            return False
    return True


def _is_query_param_passthrough(func, call: ast.Call) -> bool:
    """``conn.execute(query, *args)`` inside a non-handler function whose parameter is ``query``."""
    if _is_handler(func) or not call.args or not isinstance(call.args[0], ast.Name):
        return False
    params = {a.arg for a in _all_params(func)}
    if func.args.vararg is not None:
        params.add(func.args.vararg.arg)
    return call.args[0].id in params and (len(call.args) > 1 or bool(call.keywords))


def _url_part(node):
    """The URL expression of an HTTP call argument. ``urlopen(Request(url, data=body))`` has user
    data in the *body*, which is not SSRF; only the URL decides where the request goes."""
    if isinstance(node, ast.Call) and (_dotted(node.func) or "").rsplit(".", 1)[-1] == "Request":
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value
        return node.args[0] if node.args else None
    return node


def _is_http_call(name: str, last: str) -> bool:
    if last == "urlopen" or name.endswith("urlopen"):
        return True
    if last not in {"get", "post", "put", "delete", "patch", "head", "request", "Request"}:
        return False
    return any(m in name.lower() for m in ("requests", "httpx", "aiohttp", "session", "urllib"))


# --------------------------------------------------------------------------- JS / TS

_JS_REQ_PARTS = r"(?:query|params|body|cookies|headers|files|file)"
_JS_SOURCE = re.compile(r"\breq(?:uest)?\." + _JS_REQ_PARTS + r"\b")
_JS_ASSIGN = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*[^;]*req(?:uest)?\." + _JS_REQ_PARTS)
_JS_DESTRUCTURE = re.compile(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req(?:uest)?\." + _JS_REQ_PARTS
)
_JS_BUILT = re.compile(r"[`+]|\$\{")
_JS_SINKS = [
    ("sql_injection", re.compile(r"\.(query|execute)\s*\("), re.compile(r"[`+]|\$\{")),
    ("command_injection", re.compile(r"\b(?:child_process\.)?(?:exec|execSync)\s*\("), None),
    ("code_injection", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("), None),
    (
        "ssrf",
        re.compile(
            r"\b(?:axios|fetch)\s*\(|\bhttps?\.(?:get|request)\s*\(|"
            r"\b(?:axios|needle|got|superagent)\.(?:get|post|put|patch|delete|head|request)\s*\("
        ),
        None,
    ),
    (
        "path_traversal",
        re.compile(
            r"\bfs\.(?:readFile|readFileSync|createReadStream|writeFile)\s*\(|\.sendFile\s*\("
        ),
        None,
    ),
    ("open_redirect", re.compile(r"\.redirect\s*\("), None),
]


def _js_extra(relpath: str, lines: list[str], tainted: set[str]) -> list[TaintFinding]:
    return [
        TaintFinding(vuln, SEVERITY[vuln], 0.5, relpath, lineno, sink, snippet)
        for vuln, lineno, sink, snippet in xd.js_findings(lines, tainted)
    ]


def _js_taint(relpath: str, text: str) -> list[TaintFinding]:
    lines = text.splitlines()
    tainted: set[str] = set()
    built: set[str] = set()  # tainted variables assigned from a concatenation / template
    for line in lines:
        for m in _JS_ASSIGN.finditer(line):
            tainted.add(m.group(1))
            if _JS_BUILT.search(line):
                built.add(m.group(1))
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
            built_here = any(re.search(r"\b" + re.escape(v) + r"\b", line) for v in built)
            if (
                m
                and (extra_re is None or extra_re.search(line) or built_here)
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
    have = {(f.vuln_type, f.line) for f in findings}
    findings.extend(
        f for f in _js_extra(relpath, lines, tainted) if (f.vuln_type, f.line) not in have
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


_HTTP_SERVER_METHODS = frozenset(
    {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_HEAD", "do_PATCH", "do_OPTIONS"}
)
_HTTP_SERVER_SOURCES = frozenset({"path", "headers", "rfile"})


def _mark_http_server_handlers(tree: ast.AST) -> None:
    """``BaseHTTPRequestHandler.do_GET``: the request is ``self.path`` / ``self.headers`` /
    ``self.rfile``. Mark the method as a handler and those attribute reads as request input."""
    for func in ast.walk(tree):
        if isinstance(func, ast.FunctionDef) and func.name in _HTTP_SERVER_METHODS:
            func._sa_handler = True  # type: ignore[attr-defined]
            for node in ast.walk(func):
                if (
                    isinstance(node, ast.Attribute)
                    and node.attr in _HTTP_SERVER_SOURCES
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "self"
                ):
                    node._sa_source = True  # type: ignore[attr-defined]


def _mark_constant_lookups(tree: ast.AST) -> None:
    """Mark ``CONFIG[key]`` / ``CONFIG.get(key)`` where CONFIG is a module-level dict literal.

    The result is one of the program's own constants whatever ``key`` is (a missing key raises or
    yields None), so it is not attacker-shaped -- the usual "dataset name selects a config" idiom.
    A name that is rebound anywhere else, or written into through a subscript, is not constant."""
    names: set[str] = set()
    for stmt in getattr(tree, "body", []):
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Dict):
            names.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.value, ast.Dict)
            and isinstance(stmt.target, ast.Name)
        ):
            names.add(stmt.target.id)
    if not names:
        return
    stores: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1
        elif (  # CONFIG["k"] = ... mutates it
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Store)
            and isinstance(node.value, ast.Name)
        ):
            stores[node.value.id] = stores.get(node.value.id, 0) + 2
    names = {n for n in names if stores.get(n, 0) == 1}  # exactly the one module-level binding
    if not names:
        return
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.ctx, ast.Load)
            and isinstance(node.value, ast.Name)
            and node.value.id in names
        ) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in names
        ):
            node._sa_const = True  # type: ignore[attr-defined]


def mark_view_handlers(tree: ast.AST) -> None:
    """Mark request-handling methods of Django/DRF class-based views so the taint and IDOR
    analysers treat them as handlers. Methods of a view whose ``get_queryset`` filters by
    the requesting user are additionally marked ``_sa_scoped`` (ownership enforced there)."""
    _mark_constant_lookups(tree)
    _mark_http_server_handlers(tree)
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        bases = [_dotted(b) or "" for b in cls.bases]
        if not any(b.endswith(_CBV_BASE_HINTS) for b in bases):
            continue
        scoped = _get_queryset_scopes_to_user(cls)
        for item in cls.body:
            if (
                isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name.lower() in _CBV_METHOD_MAP
            ):
                item._sa_handler = True  # type: ignore[attr-defined]
                item._sa_scoped = scoped  # type: ignore[attr-defined]


def _get_queryset_scopes_to_user(cls: ast.ClassDef) -> bool:
    for item in cls.body:
        if (
            isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == "get_queryset"
        ):
            for node in ast.walk(item):
                if isinstance(node, (ast.Attribute, ast.Name)) and "request.user" in (
                    _dotted(node) or ""
                ):
                    return True
    return False


def _all_function_nodes(tree: ast.AST) -> list:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _is_handler(func) -> bool:
    if getattr(func, "_sa_handler", False):  # class-based view method (see mark_view_handlers)
        return True
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


# Calls whose result cannot carry an injection payload. Numeric casts and UUID parsing always
# neutralise; quoting/basename helpers are accepted globally too (taint here is not tracked per
# vulnerability kind), so a value shell-quoted and then reused in SQL would be missed -- rare, and
# documented in docs/static-analysis.md.
_SANITIZER_NAMES = {"int", "float", "bool", "Decimal", "UUID", "len", "ord", "escape"}
_SANITIZER_DOTTED = (
    "shlex.quote",
    "pipes.quote",
    "secure_filename",
    "os.path.basename",
    "posixpath.basename",
    "ntpath.basename",
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
)


_PATH_CLASSES = {"Path", "PurePath", "PurePosixPath", "PureWindowsPath"}


def _is_basename_or_char_filter(n: ast.AST) -> bool:
    """``Path(x).name`` (a basename) and ``"".join(c if c.isalnum() else "_" for c in x)`` (a
    character whitelist) cannot carry a path separator, so they neutralise path traversal."""
    if (
        isinstance(n, ast.Attribute)
        and n.attr == "name"
        and isinstance(n.value, ast.Call)
        and (_dotted(n.value.func) or "").rsplit(".", 1)[-1] in _PATH_CLASSES
    ):
        return True
    if (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "join"
        and isinstance(n.func.value, ast.Constant)
        and n.func.value.value == ""
        and n.args
        and isinstance(n.args[0], ast.GeneratorExp)
    ):
        elt = n.args[0].elt
        test = elt.test if isinstance(elt, ast.IfExp) else None
        if test is not None:
            return any(
                isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute)
                and c.func.attr in {"isalnum", "isalpha", "isdigit"}
                for c in ast.walk(test)
            )
    return False


def _is_sanitizer_call(call: ast.Call) -> bool:
    name = _dotted(call.func) or ""
    if name.rsplit(".", 1)[-1] in _SANITIZER_NAMES:
        return True
    return any(name == d or name.endswith("." + d) for d in _SANITIZER_DOTTED)


def _iter_unsanitized(node: ast.expr, sanitize: bool = True, ctx: _Ctx | None = None):
    """Walk an expression but do not descend into the arguments of sanitizing calls."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        if getattr(n, "_sa_const", False):
            continue  # a lookup into the program's own constant table
        if _is_basename_or_char_filter(n):
            continue
        if isinstance(n, ast.IfExp):
            # `"DESC" if request.args.get("dir") == "desc" else "ASC"`: the test only *selects*
            # between the branches; the value is whichever branch, not the request data.
            stack.extend((n.body, n.orelse))
            continue
        if sanitize and isinstance(n, ast.Call) and _is_sanitizer_call(n):
            continue
        if (
            ctx is not None
            and isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in ctx.functions
        ):
            # A call to a function defined in this file: whether it returns request data is
            # decided by its body (_call_returns_tainted), not by merely receiving a tainted
            # argument -- `_cfg(name)` returns a constant config entry however `name` is chosen.
            continue
        if isinstance(n, ast.Call) and (_dotted(n.func) or "").rsplit(".", 1)[-1] == "Request":
            # urllib/requests Request(url, data=..., headers=...): only the URL decides where it
            # goes; user data in the body or headers does not make the *request object* a URL.
            stack.append(n.func)
            url = (
                n.args[0] if n.args else next((k.value for k in n.keywords if k.arg == "url"), None)
            )
            if url is not None:
                stack.append(url)
            continue
        stack.extend(ast.iter_child_nodes(n))


def _expr_tainted(
    node: ast.expr, tainted: set[str], ctx: _Ctx | None = None, sanitize: bool = True
) -> bool:
    """True if the expression carries request-controlled data.

    ``sanitize=False`` ignores sanitizers: access-control analysis asks "does the *client choose*
    this id", and ``int(order_id)`` is still client-chosen even though it cannot inject."""
    for sub in _iter_unsanitized(node, sanitize, ctx):
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
    if getattr(node, "_sa_source", False):
        return True
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
