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
from dataclasses import dataclass, replace

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "websocket"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Names that indicate an authorization/authentication check is applied.
AUTH_HINT = re.compile(
    r"(?i)(auth|login_required|jwt_required|require[_s]?|current_?user|permission|"
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


# Paths that are public on purpose: capability URLs (a secret token in the path), sign-in and
# sign-up, token refresh, health probes, provider webhooks/callbacks, explicitly "public" areas.
PUBLIC_BY_DESIGN = re.compile(
    r"(?i)(?:[{<:]\s*(?:token|code|slug|key|share_?id|invite)\b)"
    r"|/(?:login|logout|signin|sign-in|register|signup|sign-up|refresh|health|healthz|ready|"
    r"readyz|ping|status|webhooks?|callback|inbound|public|oauth|forgot)(?:/|$|\b)"
)


def route_findings(routes: list[Route]) -> list[RouteFinding]:
    findings: list[RouteFinding] = []
    for r in routes:
        if r.protected or PUBLIC_BY_DESIGN.search(r.path):
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
    router_guards = _router_guards(tree)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            guard = _python_handler_guard(node)
            for dec in node.decorator_list:
                for method, path, dec_guard in _python_route_decorator(dec):
                    g = guard or dec_guard or router_guards.get(_decorator_receiver(dec) or "")
                    routes.append(
                        Route(
                            method,
                            path,
                            "python",
                            relpath,
                            node.lineno,
                            node.name,
                            g is not None,
                            g,
                        )
                    )
            routes.extend(_drf_function_routes(node, relpath))
        elif isinstance(node, ast.ClassDef):
            routes.extend(_django_cbv_routes(node, relpath))
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


# --------------------------------------------------------------------------- Django

# Django/DRF class-based view bases and the method names that handle requests.
_CBV_BASE_HINTS = ("APIView", "ViewSet", "GenericAPIView", "View", "ListView", "DetailView")
_CBV_METHOD_MAP = {
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "head": "HEAD",
    "options": "OPTIONS",
    # DRF ViewSet actions:
    "list": "GET",
    "create": "POST",
    "retrieve": "GET",
    "update": "PUT",
    "partial_update": "PATCH",
    "destroy": "DELETE",
}
_AUTH_DECORATOR = re.compile(r"(?i)(login_required|permission_required|user_passes_test)")


def _str_list(node: ast.expr | None) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple)):
        return [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
    return []


def _drf_function_routes(func, relpath: str):
    """DRF function views: @api_view(['POST', ...]) with optional permission decorators."""
    routes: list[Route] = []
    for dec in func.decorator_list:
        if not (isinstance(dec, ast.Call) and (_dotted_name(dec.func) or "").endswith("api_view")):
            continue
        methods = _str_list(dec.args[0]) if dec.args else ["GET"]
        guard = _drf_function_guard(func)
        for m in methods:
            routes.append(
                Route(
                    m.upper(),
                    f"/{func.name}",
                    "django",
                    relpath,
                    func.lineno,
                    func.name,
                    guard is not None,
                    guard,
                )
            )
    return routes


def _drf_function_guard(func) -> str | None:
    for dec in func.decorator_list:
        name = _dotted_name(dec.func if isinstance(dec, ast.Call) else dec) or ""
        if _AUTH_DECORATOR.search(name):
            return name
        if isinstance(dec, ast.Call) and name.endswith(
            ("permission_classes", "authentication_classes")
        ):
            classes = _str_cls_names(dec.args[0]) if dec.args else []
            if classes and not all(c.endswith("AllowAny") for c in classes):
                return name
    return None


def _django_cbv_routes(cls: ast.ClassDef, relpath: str):
    bases = [_dotted_name(b) or "" for b in cls.bases]
    if not any(b.endswith(_CBV_BASE_HINTS) for b in bases):
        return []
    protected, guard = _cbv_protection(cls, bases)
    routes: list[Route] = []
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            method = _CBV_METHOD_MAP.get(item.name.lower())
            if method:
                routes.append(
                    Route(
                        method,
                        f"/{cls.name}/{item.name}",
                        "django",
                        relpath,
                        item.lineno,
                        f"{cls.name}.{item.name}",
                        protected,
                        guard,
                    )
                )
    return routes


def _cbv_protection(cls: ast.ClassDef, bases: list[str]) -> tuple[bool, str | None]:
    if any(b.endswith(("LoginRequiredMixin", "PermissionRequiredMixin")) for b in bases):
        return True, "LoginRequiredMixin"
    for item in cls.body:
        if isinstance(item, ast.Assign):
            for t in item.targets:
                if isinstance(t, ast.Name) and t.id in {
                    "permission_classes",
                    "authentication_classes",
                }:
                    classes = _str_cls_names(item.value)
                    if classes and not all(c.endswith("AllowAny") for c in classes):
                        return True, t.id
    return False, None


def _str_cls_names(node: ast.expr | None) -> list[str]:
    if isinstance(node, (ast.List, ast.Tuple)):
        return [n for e in node.elts if (n := _dotted_name(e))]
    return []


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
    # 4) The handler itself enforces access: it calls an ownership/permission helper, compares an
    #    owner attribute, or explicitly denies with 401/403.
    return _body_guard(node)


# Helper names that load-or-deny: _get_owned_cat(cat_id, user), ensure_member(...), ...
_GUARD_CALL = re.compile(
    r"(?i)^_?(verify|ensure|require|authori[sz]e|authenticate|enforce|can_|get_owned|load_owned|owned)"
    r"|^_?check_(owner|ownership|access|permission|auth|member|user|role|consent)"
    r"|owner|ownership|permission"
)  # not `check_output` / `check_call`: those are subprocess helpers, not access checks
_OWNER_ATTRS = {"owner_id", "user_id", "account_id", "tenant_id", "org_id", "created_by", "owner"}


def _session_gate(test: ast.expr) -> bool:
    """``'username' not in g.session`` / ``not session.get('user')`` / ``not session['uid']``."""

    def is_session(n: ast.AST) -> bool:
        root = _dotted_name(n) if isinstance(n, (ast.Name, ast.Attribute)) else None
        return bool(root) and root.rsplit(".", 1)[-1] == "session"

    if isinstance(test, ast.Compare) and any(isinstance(o, ast.NotIn) for o in test.ops):
        return any(is_session(c) for c in test.comparators)
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        while isinstance(inner, (ast.Call, ast.Subscript, ast.Attribute)):
            inner = inner.func if isinstance(inner, ast.Call) else inner.value
            if is_session(inner):
                return True
    return False


def _body_guard(func: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for node in ast.walk(func):
        if (
            isinstance(node, ast.If)
            and node.body
            and isinstance(node.body[-1], (ast.Return, ast.Raise))
            and _session_gate(node.test)
        ):
            return "in-handler check: session gate"
        if isinstance(node, ast.Call):
            name = (_dotted_name(node.func) or "").rsplit(".", 1)[-1]
            if name and _GUARD_CALL.search(name):
                return f"in-handler check: {name}()"
            # raise HTTPException(status_code=403) / abort(401) is an explicit access decision
            if name in {"HTTPException", "abort", "PermissionDenied"}:
                for arg in [*node.args, *(k.value for k in node.keywords)]:
                    if isinstance(arg, ast.Constant) and arg.value in {401, 403}:
                        return "in-handler check: explicit 401/403"
                    if isinstance(arg, ast.Attribute) and arg.attr in {
                        "HTTP_401_UNAUTHORIZED",
                        "HTTP_403_FORBIDDEN",
                    }:
                        return "in-handler check: explicit 401/403"
        elif isinstance(node, ast.Compare):
            for side in [node.left, *node.comparators]:
                if isinstance(side, ast.Attribute) and side.attr in _OWNER_ATTRS:
                    return f"in-handler check: compares .{side.attr}"
    return None


def _depends_guard_in(call: ast.Call) -> str | None:
    for kw in call.keywords:
        if kw.arg == "dependencies" and isinstance(kw.value, (ast.List, ast.Tuple)):
            for elt in kw.value.elts:
                g = _depends_name(elt)
                if g:
                    return g
    return None


# Dependency names that guard access without containing "auth": verify_cat_owner, check_access,
# require_member ... Used only for names passed to Depends()/Security().
DEPENDS_HINT = re.compile(
    r"(?i)(verify|owner|owned|ownership|access|role|scope|member|principal|identity|tenant|acl|"
    r"rbac|can_|check_|authoriz|current)"
)
# `get_current_user_optional`: resolves the user when present but does not require one.
_OPTIONAL_GUARD = re.compile(r"(?i)optional|maybe|anonymous|allow_?anon|opt_")


def _is_guard_dependency(name: str) -> bool:
    if _OPTIONAL_GUARD.search(name):
        return False
    return bool(AUTH_HINT.search(name) or DEPENDS_HINT.search(name))


def _depends_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Call) and _dotted_name(node.func) in {"Depends", "Security"}:
        inner = node.args[0] if node.args else None
        name = _dotted_name(inner) if inner is not None else None
        if name and _is_guard_dependency(name):
            return name
    return None


def _router_guards(tree: ast.AST) -> dict[str, str]:
    """``router = APIRouter(..., dependencies=[Depends(guard)])`` guards every route on it."""
    guards: dict[str, str] = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and (_dotted_name(node.value.func) or "").rsplit(".", 1)[-1] in {"APIRouter", "FastAPI"}
        ):
            guard = _depends_guard_in(node.value)
            if guard:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        guards[target.id] = guard
    return guards


def _decorator_receiver(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
        base = dec.func.value
        return base.id if isinstance(base, ast.Name) else None
    return None


def apply_include_guards(routes: list[Route], sources: list[tuple[str, str]]) -> list[Route]:
    """``app.include_router(mod.router, dependencies=[Depends(guard)])`` protects the routes
    defined in that module. Resolved by import path where possible, else by module name."""
    guards: list[
        tuple[str, str | None, str]
    ] = []  # (module path or stem, same-file relpath, guard)
    for relpath, text in sources:
        if not relpath.endswith(".py") or "include_router" not in text:
            continue
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            continue
        imports: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "include_router"
                and node.args
            ):
                continue
            guard = _depends_guard_in(node)
            if not guard:
                continue
            target = node.args[0]
            if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                module = imports.get(target.value.id, target.value.id)
                guards.append((module, None, guard))
            elif isinstance(target, ast.Name):
                dotted = imports.get(target.id)
                if dotted:  # `from pkg.mod import router [as alias]` -> pkg.mod
                    guards.append((dotted.rsplit(".", 1)[0], None, guard))
                else:  # router defined in this very file
                    guards.append(("", relpath, guard))
    if not guards:
        return routes

    def matches(route: Route, module: str, same_file: str | None) -> bool:
        if same_file is not None:
            return route.relpath == same_file
        suffix = module.replace(".", "/")
        stem = module.rsplit(".", 1)[-1]
        path = route.relpath[:-3] if route.relpath.endswith(".py") else route.relpath
        return (
            path.endswith(suffix)
            or path.endswith(suffix + "/__init__")
            or path.rsplit("/", 1)[-1] == stem
        )

    out: list[Route] = []
    for r in routes:
        if not r.protected:
            for module, same_file, guard in guards:
                if matches(r, module, same_file):
                    r = replace(r, protected=True, guard=f"include_router(dependencies={guard})")
                    break
        out.append(r)
    return out


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


_JS_SERVER = re.compile(
    r"""(?x)(?:require\(\s*|from\s+|import\s+)['"](?:express|fastify|koa|koa-router|@koa/router|
    restify|hapi|@hapi/hapi|polka|hono|@nestjs/\w+)['"]|\bexpress\s*\(|\bRouter\s*\(|\bFastify\s*\("""
)


def _js_routes(relpath: str, text: str) -> list[Route]:
    routes: list[Route] = []
    # `api.put("/settings")` in a client component is an HTTP *call*, not a route definition: an
    # `api` receiver counts only in a file that uses a server framework (and is not a component).
    is_server = _JS_SERVER.search(text) is not None and not relpath.endswith((".jsx", ".tsx"))
    for m in _JS_ROUTE.finditer(text):
        if m.group(0).startswith("api.") and not is_server:
            continue  # an `api` client object, not a router
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
    routes.extend(_nest_routes(relpath, text))
    return routes


# NestJS: @Controller('prefix') on a class, @Get()/@Post('x')/... on methods, auth via
# @UseGuards(...) (class- or method-level) unless @Public() overrides it.
_NEST_CONTROLLER = re.compile(r"@Controller\(\s*['\"`]?([^'\"`)]*)")
_NEST_METHOD = re.compile(r"@(Get|Post|Put|Patch|Delete|All)\(\s*(?:['\"`]([^'\"`]*)['\"`])?\s*\)")


def _nest_routes(relpath: str, text: str) -> list[Route]:
    if "@Controller" not in text and not _NEST_METHOD.search(text):
        return []
    lines = text.splitlines()
    cm = _NEST_CONTROLLER.search(text)
    prefix = (cm.group(1).strip("/") if cm else "") or ""
    controller_line = text.count("\n", 0, cm.start()) + 1 if cm else 0
    # Class-level guard appears between @Controller and the first route decorator.
    first_method = _NEST_METHOD.search(text)
    first_method_line = (
        text.count("\n", 0, first_method.start()) + 1 if first_method else len(lines)
    )
    # Class decorators may sit above or below @Controller (@ApiTags, @UseGuards, ...).
    class_line = next(
        (i + 1 for i in range(max(controller_line - 1, 0), len(lines)) if " class " in lines[i]),
        first_method_line,
    )
    class_guarded = any(
        "@UseGuards" in lines[i]
        for i in range(max(controller_line - 10, 0), min(class_line, len(lines)))
    )

    routes: list[Route] = []
    for m in _NEST_METHOD.finditer(text):
        verb = m.group(1).upper()
        method = "ANY" if verb == "ALL" else verb
        sub = (m.group(2) or "").strip("/")
        path = "/" + "/".join(p for p in (prefix, sub) if p)
        line = text.count("\n", 0, m.start()) + 1
        window = "\n".join(lines[max(line - 6, 0) : line])  # decorators just above the method
        method_guarded = "@UseGuards" in window
        public = "@Public" in window
        protected = (method_guarded or (class_guarded and not public)) and not public
        routes.append(
            Route(
                method,
                path,
                "nestjs",
                relpath,
                line,
                "",
                protected,
                "@UseGuards" if protected else None,
            )
        )
    return routes
