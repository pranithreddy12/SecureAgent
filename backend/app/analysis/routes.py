"""Extract HTTP routes from source and flag endpoints with no visible authorization.

Part of the grey-box Application Model (ADR-008). Python routes are parsed with the
standard-library ``ast`` (deterministic, no dependency); JS/TS routes are matched
heuristically. This finds *broken function-level access control* candidates — a core
business-logic flaw class — but authorization may also be applied by global middleware
that static analysis cannot see, so findings are deliberately low-confidence and framed
as "review", never "confirmed".
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "websocket"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Names that indicate an authorization/authentication check is applied.
AUTH_HINT = re.compile(
    r"(?i)(auth|login_required|jwt_required|require[_s]?|current_user|permission|"
    r"is_authenticated|verify_token|ensure_|protected|bearer|oauth|admin_required|"
    r"session_required|authenticated|guard|restrict)"
)
# Endpoints whose path suggests a sensitive action; flagged even for GET.
PRIVILEGED_PATH = re.compile(
    r"(?i)(admin|internal|users?|accounts?|password|roles?|config|settings|billing|"
    r"payments?|delete|remove|grant|revoke|token|secret|keys?|export|impersonate)"
)

_JS_ROUTE = re.compile(
    r"""\b(?:app|router|api|server)\.(get|post|put|patch|delete|all)\s*\(\s*"""
    r"""(['"`])(?P<path>[^'"`]+)\2(?P<rest>[^)]*)""",
)


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    framework: str
    relpath: str
    line: int
    handler: str
    protected: bool
    guard: str | None  # what signalled protection, if anything


@dataclass(frozen=True)
class RouteFinding:
    route: Route
    severity: str
    confidence: float
    reason: str

    @property
    def title(self) -> str:
        return f"Endpoint without visible authorization: {self.route.method} {self.route.path}"


def extract_routes(relpath: str, text: str) -> list[Route]:
    if relpath.endswith((".py",)):
        return _python_routes(relpath, text)
    if relpath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return _js_routes(relpath, text)
    return []


def route_findings(routes: list[Route]) -> list[RouteFinding]:
    findings: list[RouteFinding] = []
    for r in routes:
        if r.protected:
            continue
        privileged = bool(PRIVILEGED_PATH.search(r.path))
        if r.method not in STATE_CHANGING and not privileged:
            continue  # plain GET of a non-sensitive path: too noisy to flag
        severity = "high" if (r.method in STATE_CHANGING and privileged) else "medium"
        findings.append(
            RouteFinding(
                route=r,
                severity=severity,
                confidence=0.4,  # global middleware may protect it; this is a review signal
                reason=(
                    "No authorization dependency/decorator/middleware was detected on this "
                    "endpoint. Confirm it is protected (it may be enforced globally, which "
                    "this static check cannot see)."
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- Python


def _python_routes(relpath: str, text: str) -> list[Route]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    routes: list[Route] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        guard = _python_handler_guard(node)
        for dec in node.decorator_list:
            for method, path, dec_guard in _python_route_decorator(dec):
                g = guard or dec_guard
                routes.append(
                    Route(
                        method=method,
                        path=path,
                        framework="python",
                        relpath=relpath,
                        line=node.lineno,
                        handler=node.name,
                        protected=g is not None,
                        guard=g,
                    )
                )
    return routes


def _python_route_decorator(dec: ast.expr):
    """Yield (METHOD, path, decorator_guard) for a route decorator, else nothing."""
    if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
        return
    attr = dec.func.attr.lower()
    if attr not in HTTP_METHODS and attr != "route":
        return
    path = None
    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
        path = dec.args[0].value
    if path is None:
        return
    # A dependencies=[Depends(auth)] kwarg on the decorator counts as a guard.
    dec_guard = _depends_guard_in(dec)
    if attr == "route":  # Flask-style: methods=[...]
        methods = _flask_methods(dec) or ["GET"]
        for m in methods:
            yield m.upper(), path, dec_guard
    else:
        yield attr.upper(), path, dec_guard


def _flask_methods(dec: ast.Call) -> list[str]:
    for kw in dec.keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            return [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
    return []


def _python_handler_guard(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    # 1) An auth-looking decorator (e.g. @login_required, @require_admin).
    for dec in node.decorator_list:
        name = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec)
        if name and AUTH_HINT.search(name) and not _is_route_name(name):
            return name
    # 2) A FastAPI dependency in the signature (Depends(get_current_user), etc.).
    for default in list(node.args.defaults) + list(node.args.kw_defaults):
        g = _depends_name(default)
        if g:
            return g
    # 3) A type annotation that is itself an auth dependency alias.
    for arg in node.args.args + node.args.kwonlyargs:
        if arg.annotation is not None:
            n = _dotted_name(arg.annotation)
            if n and AUTH_HINT.search(n) and ("user" in n.lower() or "current" in n.lower()):
                return n
    return None


def _depends_guard_in(call: ast.Call) -> str | None:
    for kw in call.keywords:
        if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for elt in kw.value.elts:
                g = _depends_name(elt)
                if g:
                    return g
    return None


def _depends_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Call) and _dotted_name(node.func) in {"Depends", "Security"}:
        inner = node.args[0] if node.args else None
        name = _dotted_name(inner) if inner is not None else None
        if name and AUTH_HINT.search(name):
            return name
    return None


def _dotted_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_route_name(name: str) -> bool:
    last = name.split(".")[-1].lower()
    return last in HTTP_METHODS or last == "route"


# --------------------------------------------------------------------------- JS / TS


def _js_routes(relpath: str, text: str) -> list[Route]:
    routes: list[Route] = []
    for m in _JS_ROUTE.finditer(text):
        method = m.group(1).upper()
        if method == "ALL":
            method = "ANY"
        rest = m.group("rest") or ""
        # Middleware args between the path and the handler; an auth-looking one = guard.
        guard = None
        for token in re.findall(r"[A-Za-z_$][A-Za-z0-9_$.]*", rest):
            if AUTH_HINT.search(token):
                guard = token
                break
        line = text.count("\n", 0, m.start()) + 1
        routes.append(
            Route(
                method=method,
                path=m.group("path"),
                framework="javascript",
                relpath=relpath,
                line=line,
                handler="",
                protected=guard is not None,
                guard=guard,
            )
        )
    return routes
