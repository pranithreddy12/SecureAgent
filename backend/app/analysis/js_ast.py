"""Syntax-tree taint analysis for JavaScript/TypeScript (optional ``secureagent[js]`` extra).

The default JS engine (``taint._js_taint``) is regex-based and file-scoped: it cannot see that a
value travels into a helper function, and it only knows a tainted name appears *somewhere* in the
sink's statement. When tree-sitter is installed this engine adds, on top of it:

* per-function scope (a name tainted in one handler does not taint another function's variable);
* the sink's actual arguments are checked (``db.query(sql, [id])`` is parameterised);
* one-hop interprocedural flow into same-file helpers (``run(req.query.q)`` -> ``function run(q)``).

Its findings are *added* to the regex engine's (de-duplicated by type and line); it never removes
one, so installing the extra can only raise recall. Status/confidence follow the same honesty
model: these are "likely/suspicious", never confirmed.
"""

from __future__ import annotations

import re

from app.analysis.taint import _JS_REDIRECT_CHECK, _JS_SINKS, SEVERITY, TaintFinding

try:  # optional dependency
    import tree_sitter
    import tree_sitter_javascript
    import tree_sitter_typescript

    _LANGS = {
        "js": tree_sitter.Language(tree_sitter_javascript.language()),
        "ts": tree_sitter.Language(tree_sitter_typescript.language_typescript()),
        "tsx": tree_sitter.Language(tree_sitter_typescript.language_tsx()),
    }
    AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _LANGS = {}
    AVAILABLE = False

_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
}
_REQUEST_NAMES = {"req", "request"}
_REQUEST_PARTS = {"query", "params", "body", "cookies", "headers", "files", "file"}
_SANITIZER = re.compile(
    r"^(?:\w+\.)*(?:esc\w*|escape\w*|sanitize\w*|purify|encodeURI\w*|parseInt|parseFloat|Number|"
    r"Boolean|validator\.\w+|path\.basename|DOMPurify\.sanitize)$"
)
MAX_DEPTH = 2


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _lang_for(relpath: str) -> str:
    if relpath.endswith(".tsx"):
        return "tsx"
    if relpath.endswith(".ts"):
        return "ts"
    return "js"


def _walk(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _walk_scope(node):
    """Descendants of a function body without entering nested functions."""
    stack = list(reversed(node.children))
    while stack:
        n = stack.pop()
        yield n
        if n.type not in _FUNCTIONS:
            stack.extend(reversed(n.children))


def _is_source(node) -> bool:
    """``req.query.x`` / ``request.body`` / ``await request.json()`` / ``searchParams.get('q')``."""
    if node.type == "member_expression":
        parts = []
        cur = node
        while cur is not None and cur.type == "member_expression":
            prop = cur.child_by_field_name("property")
            parts.append(_text(prop) if prop else "")
            cur = cur.child_by_field_name("object")
        if cur is not None and cur.type == "identifier" and _text(cur) in _REQUEST_NAMES:
            return bool(set(parts) & _REQUEST_PARTS)
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        name = _text(fn) if fn else ""
        if re.fullmatch(r"(?:req|request)\.(?:json|formData|text)", name):
            return True
        if re.fullmatch(r"(?:\w+\.)?searchParams\.(?:get|getAll)", name):
            return True
    return False


def _tainted_expr(node, tainted: set[str]) -> bool:
    """Does the expression carry request data (not passing through a sanitizer call)?"""
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in _FUNCTIONS:
            continue
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and _SANITIZER.match(_text(fn)):
                continue
        if _is_source(n):
            return True
        if n.type in {"identifier", "shorthand_property_identifier"} and _text(n) in tainted:
            return True
        stack.extend(n.children)
    return False


def _built(node, tainted: set[str]) -> bool:
    """A string *built* from tainted data: concatenation or a template with a tainted part."""
    for n in _walk(node):
        if n.type == "template_string" and any(
            c.type == "template_substitution" and _tainted_expr(c, tainted) for c in n.children
        ):
            return True
        if n.type == "binary_expression" and _text(n.child_by_field_name("operator") or n) == "+":
            if _tainted_expr(n, tainted):
                return True
    return False


def _pattern_names(node) -> list[str]:
    """Names bound by ``x``, ``{ a, b: c }`` or ``[a, b]`` (``b: c`` binds only ``c``)."""
    if node.type == "identifier":
        return [_text(node)]
    return [
        _text(n)
        for n in _walk(node)
        if n.type in {"identifier", "shorthand_property_identifier_pattern"}
    ]


def _params(func) -> list[str]:
    params = func.child_by_field_name("parameters") or func.child_by_field_name("parameter")
    if params is None:
        return []
    if params.type == "identifier":
        return [_text(params)]
    out = []
    for p in params.named_children:
        target = p.child_by_field_name("pattern") or p
        names = _pattern_names(target) if target.type != "identifier" else [_text(target)]
        out.append(names[0] if names else "")
    return out


def _function_taint(func, initial: set[str]) -> set[str]:
    tainted = set(initial)
    assigns = []
    for n in _walk_scope(func):
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and value is not None:
                assigns.append((_pattern_names(name), value))
        elif n.type == "assignment_expression":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                assigns.append(([_text(left)], right))
    for _ in range(4):
        before = len(tainted)
        for names, value in assigns:
            if not set(names) <= tainted and _tainted_expr(value, tainted):
                tainted.update(names)
        if len(tainted) == before:
            break
    return tainted


def _sink(call, tainted: set[str]) -> tuple[str, str] | None:
    fn = call.child_by_field_name("function")
    args = call.child_by_field_name("arguments")
    if fn is None or args is None or not args.named_children:
        return None
    callee = _text(fn)
    probe = callee + "("
    if call.parent is not None and call.parent.type == "new_expression":
        probe = "new " + probe
    first = args.named_children[0]
    for vuln_type, sink_re, _extra in _JS_SINKS:
        if vuln_type == "reflected_xss" or not sink_re.search(probe):
            continue
        if vuln_type == "sql_injection":
            if _built(first, tainted) or (
                first.type == "identifier" and _text(first) in tainted and _sql_built_var(call)
            ):
                return vuln_type, callee
            continue
        if any(_tainted_expr(a, tainted) for a in args.named_children):
            if vuln_type in {"command_injection", "code_injection"} and first.type == "string":
                continue
            return vuln_type, callee
    return None


def _sql_built_var(call) -> bool:
    """``const sql = "..." + id; db.query(sql)``: the variable itself was built by concatenation."""
    args = call.child_by_field_name("arguments")
    name = _text(args.named_children[0])
    func = call.parent
    while func is not None and func.type not in _FUNCTIONS and func.type != "program":
        func = func.parent
    for n in _walk(func) if func is not None else ():
        if n.type == "variable_declarator":
            nm, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if nm is not None and value is not None and _text(nm) == name:
                return any(c.type in {"template_string", "binary_expression"} for c in _walk(value))
    return False


def analyze(relpath: str, text: str) -> list[TaintFinding]:
    if not AVAILABLE:
        return []
    parser = tree_sitter.Parser(_LANGS[_lang_for(relpath)])
    root = parser.parse(text.encode("utf-8")).root_node
    lines = text.splitlines()
    funcs = [n for n in _walk(root) if n.type in _FUNCTIONS]
    by_name: dict[str, object] = {}
    for f in funcs:
        name = f.child_by_field_name("name")
        if name is None and f.parent is not None and f.parent.type == "variable_declarator":
            name = f.parent.child_by_field_name("name")
        if name is not None:
            by_name.setdefault(_text(name), f)

    findings: dict[tuple[str, int], TaintFinding] = {}

    def visit(func, initial: set[str], depth: int, origin: tuple[str, ...]) -> None:
        tainted = _function_taint(func, initial)
        for n in _walk_scope(func):
            if n.type != "call_expression":
                continue
            hit = _sink(n, tainted)
            line = n.start_point[0] + 1
            if hit and hit[0] == "open_redirect":
                prior = "\n".join(lines[max(0, line - 9) : line])
                if _JS_REDIRECT_CHECK.search(prior):
                    hit = None  # validated just above (startsWith / allow-list), like the regex
            if hit:
                key = (hit[0], line)
                if key not in findings:
                    snippet = lines[line - 1].strip()[:160] if line <= len(lines) else ""
                    findings[key] = TaintFinding(
                        hit[0],
                        SEVERITY[hit[0]],
                        0.65,
                        relpath,
                        line,
                        hit[1],
                        snippet,
                        (*origin, f"{relpath}:{line}  {hit[1]}(…)  (sink)")[-8:],
                    )
            fn = n.child_by_field_name("function")
            callee = by_name.get(_text(fn)) if fn is not None else None
            args = n.child_by_field_name("arguments")
            if callee is None or callee is func or args is None or depth >= MAX_DEPTH:
                continue
            params = _params(callee)
            passed = {
                params[i]
                for i, a in enumerate(args.named_children)
                if i < len(params) and params[i] and _tainted_expr(a, tainted)
            }
            if passed:
                line = n.start_point[0] + 1
                step = f"{relpath}:{line}  passed to {_text(fn)}() as {', '.join(sorted(passed))}"
                visit(callee, passed, depth + 1, (*origin, step))

    for func in funcs:
        visit(func, set(), 0, (f"{relpath}  request input (req/request)",))
    return list(findings.values())
