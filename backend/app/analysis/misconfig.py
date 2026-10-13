"""Detect security misconfigurations (OWASP A05) in Python web code.

High-signal, AST-based: debug mode enabled, permissive CORS (wildcard origin combined
with credentials), disabled JWT signature verification or ``alg=none``, disabled CSRF
protection, template autoescaping turned off, and wildcard ``ALLOWED_HOSTS``. These are
definite settings present in the source, so they report as "likely". Safe variants
(DEBUG=False, explicit origins, autoescape=True, …) are not flagged.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

# category -> (cwe, owasp, remediation, severity, confidence)
CATEGORY = {
    "debug_enabled": (
        "CWE-489",
        "A05:2021 Security Misconfiguration",
        "Disable debug mode in production.",
        "medium",
        0.7,
    ),
    "permissive_cors": (
        "CWE-942",
        "A05:2021 Security Misconfiguration",
        "Do not combine a wildcard origin with credentials; allowlist specific origins.",
        "high",
        0.75,
    ),
    "jwt_verification_disabled": (
        "CWE-347",
        "A07:2021 Identification and Authentication Failures",
        "Verify JWT signatures; never disable verification or accept alg 'none'.",
        "high",
        0.85,
    ),
    "csrf_disabled": (
        "CWE-352",
        "A01:2021 Broken Access Control",
        "Enable CSRF protection for state-changing requests.",
        "medium",
        0.7,
    ),
    "template_autoescape_off": (
        "CWE-79",
        "A03:2021 Injection",
        "Enable template autoescaping to prevent XSS.",
        "medium",
        0.7,
    ),
    "allowed_hosts_wildcard": (
        "CWE-16",
        "A05:2021 Security Misconfiguration",
        "Set ALLOWED_HOSTS to explicit hostnames.",
        "medium",
        0.7,
    ),
    "container_runs_as_root": (
        "CWE-250",
        "A05:2021 Security Misconfiguration",
        "Add a non-root USER (or `user:`) so a compromised process is not root in the container.",
        "low",
        0.5,
    ),
    "privileged_container": (
        "CWE-250",
        "A05:2021 Security Misconfiguration",
        "Remove `privileged: true`; grant only the specific capabilities that are needed.",
        "medium",
        0.7,
    ),
    "csp_unsafe_inline": (
        "CWE-693",
        "A05:2021 Security Misconfiguration",
        "Remove 'unsafe-inline' from script-src/default-src; use nonces or hashes for inline code.",
        "low",
        0.5,
    ),
    "unbounded_query": (
        "CWE-770",
        "A04:2021 Insecure Design",
        "Page or cap bulk export/list endpoints (LIMIT, pagination, streaming) so one request "
        "cannot load the whole table.",
        "low",
        0.4,
    ),
    "insecure_cookie": (
        "CWE-614",
        "A05:2021 Security Misconfiguration",
        "Set Secure and HttpOnly on session/auth cookies.",
        "low",
        0.7,
    ),
}


@dataclass(frozen=True)
class MisconfigFinding:
    category: str
    rule: str
    severity: str
    confidence: float
    relpath: str
    line: int
    evidence: str

    @property
    def cwe(self) -> str:
        return CATEGORY[self.category][0]

    @property
    def owasp(self) -> str:
        return CATEGORY[self.category][1]

    @property
    def remediation(self) -> str:
        return CATEGORY[self.category][2]

    @property
    def title(self) -> str:
        return f"Security misconfiguration: {self.rule}"


_DOCKERFILE = re.compile(r"(?i)(^|/)([^/]*\.dockerfile|dockerfile[^/]*)$")
_COMPOSE = re.compile(r"(?i)(^|/)(docker-)?compose[^/]*\.ya?ml$")
_ROOT_USER = re.compile(r"""(?i)^\s*user\s*:\s*["']?(root|0)(?:[:"'\s]|$)""")
_PRIVILEGED = re.compile(r"(?i)^\s*privileged\s*:\s*[\"']?true\b")
_CSP_INLINE = re.compile(r"(?i)(script-src|default-src)[^;]*unsafe-inline")
_BULK_NAME = re.compile(r"(?i)export|download|dump|backup|csv|(?:^|[_/.-])all(?:$|[_/.-])")
_LIMIT_HINT = re.compile(
    r"(?i)\blimit\b|paginat|per_page|page_size|max_rows|fetchmany|\.first\(|islice|\[:\s*\w+\]|\.slice"
)
_ROUTE_DECORATORS = {"route", "get", "post", "put", "patch", "delete", "api_view"}
_TEXT_SUFFIXES = (
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".html",
    ".conf",
    ".yml",
    ".yaml",
)


def _infra_findings(relpath: str, text: str) -> list[MisconfigFinding]:
    """Container and header settings: root user, compose privileges, CSP unsafe-inline."""
    lines = text.splitlines()
    found: list[MisconfigFinding] = []

    def add(category: str, rule: str, line: int) -> None:
        snippet = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        sev, conf = CATEGORY[category][3], CATEGORY[category][4]
        found.append(MisconfigFinding(category, rule, sev, conf, relpath, line, snippet))

    if _DOCKERFILE.search(relpath):
        last_from, user = 0, None
        for i, raw in enumerate(lines, start=1):
            word = raw.strip().split(None, 1)
            if not word:
                continue
            if word[0].upper() == "FROM":
                last_from, user = i, None
            elif word[0].upper() == "USER" and len(word) > 1:
                user = word[1].strip().split(":")[0].lower()
        if last_from and user in (None, "root", "0"):
            add("container_runs_as_root", "Dockerfile: final stage runs as root", last_from)
    elif _COMPOSE.search(relpath):
        for i, raw in enumerate(lines, start=1):
            if _ROOT_USER.match(raw):
                add("container_runs_as_root", "compose: service runs as root", i)
            elif _PRIVILEGED.match(raw):
                add("privileged_container", "compose: privileged container", i)
    if relpath.lower().endswith(_TEXT_SUFFIXES):
        for i, raw in enumerate(lines, start=1):
            if "unsafe-inline" in raw and _CSP_INLINE.search(raw):
                add("csp_unsafe_inline", "CSP allows 'unsafe-inline' scripts", i)
    return found


def _is_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[bool, list[str]]:
    """Whether the function has a route-like decorator, and the string paths it declares."""
    paths: list[str] = []
    is_route = False
    for dec in func.decorator_list:
        call = dec if isinstance(dec, ast.Call) else None
        target = call.func if call else dec
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name in _ROUTE_DECORATORS:
            is_route = True
        if call:
            paths += [
                a.value
                for a in call.args
                if isinstance(a, ast.Constant) and isinstance(a.value, str)
            ]
    return is_route, paths


def _unbounded_findings(relpath: str, tree: ast.AST, lines: list[str]) -> list[MisconfigFinding]:
    """Bulk export/list handlers that load a whole result set with no limit."""
    out: list[MisconfigFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_route, paths = _is_route(node)
        if not is_route or not (
            _BULK_NAME.search(node.name) or any(_BULK_NAME.search(p) for p in paths)
        ):
            continue
        body = "\n".join(lines[node.lineno - 1 : node.end_lineno])
        if re.search(r"\.(fetchall|all)\(\s*\)", body) and not _LIMIT_HINT.search(body):
            snippet = lines[node.lineno - 1].strip()[:160]
            cat = CATEGORY["unbounded_query"]
            out.append(
                MisconfigFinding(
                    "unbounded_query",
                    f"{node.name}() loads an entire result set with no limit",
                    cat[3],
                    cat[4],
                    relpath,
                    node.lineno,
                    snippet,
                )
            )
    return out


def scan_misconfig(relpath: str, text: str) -> list[MisconfigFinding]:
    infra = _infra_findings(relpath, text)
    if not relpath.endswith(".py"):
        return infra
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    visitor = _Visitor(relpath, lines)
    visitor.visit(tree)
    return infra + visitor.findings + _unbounded_findings(relpath, tree, lines)


class _Visitor(ast.NodeVisitor):
    def __init__(self, relpath: str, lines: list[str]) -> None:
        self.relpath = relpath
        self.lines = lines
        self.findings: list[MisconfigFinding] = []

    def _add(self, category: str, rule: str, line: int, severity: str | None = None) -> None:
        sev = severity or CATEGORY[category][3]
        snippet = self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else ""
        self.findings.append(
            MisconfigFinding(
                category, rule, sev, CATEGORY[category][4], self.relpath, line, snippet
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            self._assignment(target, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            self._assignment(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def _assignment(self, target: ast.expr, value: ast.expr, line: int) -> None:
        key = _target_key(target)
        if key == "DEBUG" and _is_true(value):
            self._add("debug_enabled", "DEBUG = True", line)
        elif key == "debug" and _is_true(value) and isinstance(target, ast.Attribute):
            self._add("debug_enabled", "app.debug = True", line)
        elif key == "ALLOWED_HOSTS" and _contains_star(value):
            self._add("allowed_hosts_wildcard", "ALLOWED_HOSTS = ['*']", line)
        elif key in {"WTF_CSRF_ENABLED", "CSRF_ENABLED"} and _is_false(value):
            self._add("csrf_disabled", f"{key} = False", line)
        # --- Django settings ---
        elif key in _DJANGO_COOKIE_FLAGS and _is_false(value):
            self._add("insecure_cookie", f"{key} = False", line)
        elif key in {"CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL"} and _is_true(value):
            self._add("permissive_cors", f"{key} = True", line, "medium")
        elif key == "MIDDLEWARE" and _csrf_middleware_missing(value):
            self._add("csrf_disabled", "CsrfViewMiddleware missing from MIDDLEWARE", line)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._check_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._check_decorators(node)
        self.generic_visit(node)

    def _check_decorators(self, node) -> None:
        for dec in node.decorator_list:
            name = _dotted(dec.func if isinstance(dec, ast.Call) else dec) or ""
            if "csrf_exempt" in name:
                self._add("csrf_disabled", "@csrf_exempt", node.lineno)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _dotted(node.func) or ""
        last = name.rsplit(".", 1)[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}

        if last == "run" and _is_true(kw.get("debug")):
            self._add("debug_enabled", "app.run(debug=True)", node.lineno)

        origins = kw.get("allow_origins") or kw.get("origins")
        if origins is not None and _contains_star(origins):
            creds = _is_true(kw.get("allow_credentials")) or _is_true(
                kw.get("supports_credentials")
            )
            self._add(
                "permissive_cors",
                "wildcard origin with credentials" if creds else "wildcard CORS origin",
                node.lineno,
                "high" if creds else "medium",
            )

        if last == "decode" and (
            "jwt" in name.lower() or {"verify", "options", "algorithms"} & kw.keys()
        ):
            if _is_false(kw.get("verify")) or _options_no_verify(kw.get("options")):
                self._add("jwt_verification_disabled", "jwt.decode(verify=False)", node.lineno)
            if _alg_none(kw.get("algorithms")):
                self._add("jwt_verification_disabled", "jwt alg 'none'", node.lineno)
        if last == "encode" and _alg_none(kw.get("algorithm")):
            self._add("jwt_verification_disabled", "jwt.encode(algorithm='none')", node.lineno)

        if last == "set_cookie" and (_is_false(kw.get("secure")) or _is_false(kw.get("httponly"))):
            self._add("insecure_cookie", "set_cookie without Secure/HttpOnly", node.lineno)

        if last in {"Environment", "select_autoescape"} and _is_false(kw.get("autoescape")):
            self._add("template_autoescape_off", "autoescape=False", node.lineno)

        self.generic_visit(node)


# --------------------------------------------------------------------------- helpers


_DJANGO_COOKIE_FLAGS = {"SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"}


def _csrf_middleware_missing(value: ast.expr) -> bool:
    """A Django MIDDLEWARE list that is clearly a real settings list (it names other
    Django middleware) but omits CsrfViewMiddleware."""
    if not isinstance(value, (ast.List, ast.Tuple)):
        return False
    names = [
        e.value for e in value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
    ]
    looks_like_django = any("django.middleware" in n or "SessionMiddleware" in n for n in names)
    return looks_like_django and not any("CsrfViewMiddleware" in n for n in names)


def _target_key(t: ast.expr) -> str | None:
    if isinstance(t, ast.Subscript):
        k = t.slice
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            return k.value
        return None
    d = _dotted(t)
    return d.rsplit(".", 1)[-1] if d else None


def _is_true(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _contains_star(node) -> bool:
    if isinstance(node, ast.Constant):
        return node.value == "*"
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(isinstance(e, ast.Constant) and e.value == "*" for e in node.elts)
    return False


def _str_consts(node) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [
            e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)
        ]
    return []


def _alg_none(node) -> bool:
    return any(s.lower() == "none" for s in _str_consts(node))


def _options_no_verify(node) -> bool:
    if not isinstance(node, ast.Dict):
        return False
    for k, v in zip(node.keys, node.values, strict=False):
        if (
            isinstance(k, ast.Constant)
            and k.value in {"verify_signature", "verify"}
            and _is_false(v)
        ):
            return True
    return False


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
