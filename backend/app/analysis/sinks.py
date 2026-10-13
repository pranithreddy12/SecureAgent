"""Detect dangerous code patterns ("sinks") that are common sources of real
vulnerabilities: insecure deserialization, command/code execution, weak hashing,
disabled TLS verification, insecure temp files, and XXE-prone XML parsing.

Python is analysed with the standard-library ``ast`` (deterministic); JS/TS with
high-signal regexes. These flag *dangerous usage* — whether untrusted input actually
reaches the sink is confirmed later by taint analysis or dynamic testing, so findings
are framed as "review" (status suspicious), never "confirmed". Weak-crypto and
disabled-TLS findings are definite misconfigurations (status likely).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from app.analysis import extra_detectors as xd

# category -> (cwe, owasp, remediation)
CATEGORY_META = {
    "insecure_deserialization": (
        "CWE-502",
        "A08:2021 Software and Data Integrity Failures",
        "Never deserialize untrusted data. Use yaml.safe_load and JSON; avoid pickle/marshal.",
    ),
    "command_injection": (
        "CWE-78",
        "A03:2021 Injection",
        "Avoid shell=True / os.system. Pass an argument list and validate inputs.",
    ),
    "code_injection": (
        "CWE-95",
        "A03:2021 Injection",
        "Do not eval/exec dynamic input. Use safe parsers or explicit dispatch.",
    ),
    "weak_hash": (
        "CWE-327",
        "A02:2021 Cryptographic Failures",
        "Use Argon2/bcrypt for passwords and SHA-256+ for integrity; not MD5/SHA1.",
    ),
    "disabled_tls_verification": (
        "CWE-295",
        "A02:2021 Cryptographic Failures",
        "Enable certificate verification (verify=True); never disable TLS validation.",
    ),
    "insecure_temp_file": (
        "CWE-377",
        "A01:2021 Broken Access Control",
        "Use tempfile.mkstemp/NamedTemporaryFile instead of mktemp.",
    ),
    "xxe": (
        "CWE-611",
        "A05:2021 Security Misconfiguration",
        "Use defusedxml or disable external entity resolution.",
    ),
    "xss_sink": (
        "CWE-79",
        "A03:2021 Injection",
        "Do not assign untrusted data to innerHTML; use textContent or sanitize.",
    ),
    "sql_injection": (
        "CWE-89",
        "A03:2021 Injection",
        "Use parameterised queries / bound parameters; never build SQL by formatting strings.",
    ),
    "insecure_session_cookie": (
        "CWE-565",
        "A07:2021 Identification and Authentication Failures",
        "Store a random session id server-side, or sign/encrypt the cookie (itsdangerous, JWT with "
        "a secret, framework sessions); never trust a client-writable cookie as identity.",
    ),
    "plaintext_password": (
        "CWE-256",
        "A02:2021 Cryptographic Failures",
        "Hash passwords with Argon2/bcrypt/scrypt before storing or comparing them.",
    ),
    "xml_entity_expansion": (
        "CWE-776",
        "A05:2021 Security Misconfiguration",
        "Not XXE, SSRF or file disclosure: the standard-library XML parser does not load external "
        "entities. It can only be exhausted by entity expansion (denial of service), so the "
        "impact is low. Use defusedxml when parsing untrusted XML (there is no `resolve_entities` "
        "option on xml.etree's XMLParser; that is lxml).",
    ),
}

# category -> (severity, confidence, definite?)  definite => status likely, else suspicious
CATEGORY_RISK = {
    "insecure_deserialization": ("high", 0.7, False),
    "command_injection": ("high", 0.7, False),
    "code_injection": ("high", 0.7, False),
    "weak_hash": ("medium", 0.6, True),
    "disabled_tls_verification": ("high", 0.8, True),
    "insecure_temp_file": ("low", 0.6, True),
    "xxe": ("medium", 0.5, False),
    "xml_entity_expansion": ("low", 0.4, False),
    "insecure_session_cookie": ("medium", 0.5, False),
    "sql_injection": ("medium", 0.4, False),
    "plaintext_password": ("medium", 0.5, False),
    "xss_sink": ("medium", 0.4, False),
}


@dataclass(frozen=True)
class SinkFinding:
    category: str
    rule: str
    severity: str
    confidence: float
    relpath: str
    line: int
    evidence: str

    @property
    def cwe(self) -> str:
        return CATEGORY_META[self.category][0]

    @property
    def owasp(self) -> str:
        return CATEGORY_META[self.category][1]

    @property
    def remediation(self) -> str:
        return CATEGORY_META[self.category][2]

    @property
    def definite(self) -> bool:
        return CATEGORY_RISK[self.category][2]

    @property
    def title(self) -> str:
        return f"{self.category.replace('_', ' ').title()}: {self.rule}"


def _mark_nonsecurity_hashes(tree: ast.AST) -> None:
    """``int(hashlib.md5(x).hexdigest(), 16) % n`` (bucketing) and a ``.hexdigest()[:6]`` short code
    are not password/integrity uses: a numeric or truncated digest is no security boundary. The
    inner md5/sha1 call is marked so it is not reported."""

    def inner(call: ast.AST):
        # <hash>(...).hexdigest() / .digest()
        if (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr in {"hexdigest", "digest"}
            and isinstance(call.func.value, ast.Call)
        ):
            return call.func.value
        return None

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "int"
            and node.args
        ):
            target = inner(node.args[0])
            if target is not None:
                target._sa_nonsecurity_hash = True  # type: ignore[attr-defined]
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            upper = node.slice.upper
            if (
                isinstance(upper, ast.Constant)
                and isinstance(upper.value, int)
                and upper.value <= 16
            ):
                target = inner(node.value)
                if target is not None:
                    target._sa_nonsecurity_hash = True  # type: ignore[attr-defined]


def scan_sinks(relpath: str, text: str) -> list[SinkFinding]:
    if relpath.endswith(".py"):
        return _python_sinks(relpath, text)
    if relpath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return _js_sinks(relpath, text)
    return []


# --------------------------------------------------------------------------- Python


def _python_sinks(relpath: str, text: str) -> list[SinkFinding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    _mark_nonsecurity_hashes(tree)
    visitor = _SinkVisitor(relpath, lines, _collect_aliases(tree))
    visitor.const_strings = _module_string_constants(tree)
    visitor.visit(tree)
    return visitor.findings


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """Map a locally-used name to its fully-qualified module path (handles ``as`` aliases)."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


class _SinkVisitor(ast.NodeVisitor):
    def __init__(self, relpath: str, lines: list[str], aliases: dict[str, str]) -> None:
        self.relpath = relpath
        self.lines = lines
        self.aliases = aliases
        self.quoted: set[str] = set()
        self.const_strings: set[str] = set()  # module-level NAME = "literal"
        self.assigns: dict[str, list[ast.expr]] = {}  # current function: name -> assigned values
        self.findings: list[SinkFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 (ast API)
        outer, outer_assigns = self.quoted, self.assigns
        self.quoted = _quoted_names(node)  # scoped: another function may reuse the name
        self.assigns = _assignments(node)
        found = xd.plaintext_password(node)
        if found is not None:
            self._add("plaintext_password", found[1], found[0])
        self.generic_visit(node)
        self.quoted, self.assigns = outer, outer_assigns

    visit_AsyncFunctionDef = visit_FunctionDef  # noqa: N815

    def _resolve(self, name: str) -> str:
        head, sep, tail = name.partition(".")
        if head in self.aliases:
            return self.aliases[head] + (sep + tail if tail else "")
        return name

    def _add(self, category: str, rule: str, line: int) -> None:
        sev, conf, _ = CATEGORY_RISK[category]
        snippet = self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else ""
        self.findings.append(SinkFinding(category, rule, sev, conf, self.relpath, line, snippet))

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802 (ast API)
        name = self._resolve(_dotted(node.func) or "")
        last = name.rsplit(".", 1)[-1]
        kw = {k.arg: k.value for k in node.keywords if k.arg}

        # Insecure deserialization
        if last in {"load", "loads"} and re.search(r"(?:^|\.)(pickle|dill|marshal|_pickle)", name):
            self._add("insecure_deserialization", name, node.lineno)
        elif "yaml" in name and last in {"load", "unsafe_load", "full_load"}:
            if last != "load" or not _has_safe_loader(kw):
                self._add("insecure_deserialization", name or "yaml.load", node.lineno)

        # Code execution
        if name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            # eval("1 + 1") runs fixed code; only dynamic input makes it injectable.
            first = node.args[0] if node.args else None
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                self._add("code_injection", name, node.lineno)

        # Command execution
        first_arg = node.args[0] if node.args else None
        if name in {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput"}:
            if not _fixed_or_quoted(first_arg, self.quoted):
                self._add("command_injection", name, node.lineno)
        elif re.search(r"(?:^|\.)subprocess\.", name) and _is_true(kw.get("shell")):
            if not _fixed_or_quoted(first_arg, self.quoted):
                self._add("command_injection", f"{name}(shell=True)", node.lineno)

        # Disabled TLS verification
        if _is_false(kw.get("verify")):
            self._add(
                "disabled_tls_verification", f"{name or 'request'}(verify=False)", node.lineno
            )
        elif name.endswith("_create_unverified_context"):
            self._add("disabled_tls_verification", name, node.lineno)

        # Weak hashing (not when the digest is only turned into a bucket index or a short code)
        if (
            last in {"md5", "sha1"}
            and ("hashlib" in name or name == last)
            and not getattr(node, "_sa_nonsecurity_hash", False)
        ):
            self._add("weak_hash", name, node.lineno)

        # SQL assembled by string formatting (no request source needed: function arguments count)
        if last in {"execute", "executemany", "executescript", "raw"} and node.args:
            if len(node.args) == 1 and _builds_sql_string(node.args[0], self.assigns):
                self._add("sql_injection", "query built by string formatting", node.lineno)

        # Session cookie that is just an encoded, unsigned value
        cookie = xd.insecure_session_cookie(node, self.assigns)
        if cookie:
            self._add("insecure_session_cookie", cookie, node.lineno)

        # Insecure temp file
        if name.endswith("tempfile.mktemp") or (last == "mktemp" and "tempfile" in name):
            self._add("insecure_temp_file", name, node.lineno)

        # xml.sax: parser.setFeature(feature_external_ges, True) turns external entities on
        if (
            last == "setFeature"
            and len(node.args) >= 2
            and re.search(r"external_(?:ges|pes)", _dotted(node.args[0]) or "")
            and _is_true(node.args[1])
        ):
            self._add("xxe", "xml.sax setFeature(external entities, True)", node.lineno)

        # XXE-prone XML parsing
        if last in {"parse", "fromstring", "parseString"} and re.search(
            r"(?:etree|ElementTree|minidom|expat|sax|lxml)", name
        ):
            # The standard-library parsers do not fetch external entities; they remain open to
            # entity-expansion DoS. lxml resolves entities unless configured not to.
            # ... but XML that is the program's own literal (a built-in document) is not input.
            if not (first_arg is not None and _is_constant_expr(first_arg, self.const_strings)):
                self._add(
                    "xml_entity_expansion" if _is_stdlib_xml(name) else "xxe", name, node.lineno
                )

        self.generic_visit(node)


_SQL_WORDS = re.compile(
    r"(?is)\b(select\b.+\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b"
)


def _builds_sql_string(node: ast.expr, assigns: dict[str, list[ast.expr]], depth: int = 0) -> bool:
    """An SQL string that is assembled from non-literal parts (f-string, ``%``, ``+``, ``.format``).

    ``execute(text(q))`` and ``execute(q)`` with ``q`` assigned from such an expression count too."""
    if depth > 2:
        return False
    if isinstance(node, ast.Call):
        name = _dotted(node.func) or ""
        if name.rsplit(".", 1)[-1] in {"text", "sql", "SQL"} and node.args:
            return _builds_sql_string(node.args[0], assigns, depth + 1)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = node.func.value
            return (
                isinstance(base, ast.Constant)
                and isinstance(base.value, str)
                and bool(_SQL_WORDS.search(base.value))
                and any(not isinstance(a, ast.Constant) for a in node.args)
            )
        return False
    if isinstance(node, ast.Name):
        return any(_builds_sql_string(v, assigns, depth + 1) for v in assigns.get(node.id, []))
    literal = " ".join(
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )
    if not _SQL_WORDS.search(literal):
        return False
    if isinstance(node, ast.JoinedStr):
        parts = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
        return any(not _is_numeric_value(p, assigns) for p in parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        leaves: list[ast.expr] = []
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)):
                stack += [n.left, n.right]
            elif isinstance(n, ast.Tuple):
                stack += list(n.elts)
            elif not isinstance(n, ast.Constant):
                leaves.append(n)
        return any(not _is_numeric_value(p, assigns) for p in leaves)
    return False


def _is_numeric_value(node: ast.expr, assigns: dict[str, list[ast.expr]]) -> bool:
    """``int(x)``, ``str(int(x))``, ``len(x)`` or a name only ever assigned from those."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in {"int", "float", "len", "bool"}:
            return True
        if node.func.id == "str" and node.args:
            return _is_numeric_value(node.args[0], assigns)
    if isinstance(node, ast.Name):
        values = assigns.get(node.id, [])
        return bool(values) and all(
            isinstance(v, ast.Call)
            and isinstance(v.func, ast.Name)
            and v.func.id in {"int", "float", "len", "bool"}
            for v in values
        )
    return False


def _assignments(func: ast.AST) -> dict[str, list[ast.expr]]:
    """name -> every expression assigned to it inside ``func``."""
    out: dict[str, list[ast.expr]] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out.setdefault(t.id, []).append(node.value)
    return out


def _module_string_constants(tree: ast.AST) -> set[str]:
    """Names assigned a string/bytes literal at module level and bound nowhere else (a rebinding
    inside a function, even through ``global``, makes the value input-dependent)."""
    literal: set[str] = set()
    for stmt in getattr(tree, "body", []):
        if (
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, (str, bytes))
        ):
            literal.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
    stores: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1
    return {n for n in literal if stores.get(n, 0) == 1}


def _is_constant_expr(node: ast.expr, consts: set[str]) -> bool:
    """A literal, a module-level string constant, or a pure transformation of those
    (``USERS_XML.encode()``, ``io.BytesIO(DOC)``)."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        return node.id in consts
    if isinstance(node, ast.Call):
        func_ok = (
            _is_constant_expr(node.func.value, consts)
            if isinstance(node.func, ast.Attribute)
            else isinstance(node.func, ast.Name | ast.Attribute)
        )
        return func_ok and bool(node.args) and all(_is_constant_expr(a, consts) for a in node.args)
    if isinstance(node, ast.Attribute):
        return _is_constant_expr(node.value, consts)
    return False


_QUOTERS = {"shlex.quote", "pipes.quote"}


def _quoted_names(tree: ast.AST) -> set[str]:
    """Names whose every assignment in this function is a shell-quoting call."""
    quoted: set[str] = set()
    other: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            is_quote = isinstance(node.value, ast.Call) and (_dotted(node.value.func) in _QUOTERS)
            for t in node.targets:
                if isinstance(t, ast.Name):
                    (quoted if is_quote else other).add(t.id)
    return quoted - other


def _fixed_or_quoted(node, quoted: frozenset[str] | set[str] = frozenset()) -> bool:
    """True if a shell command is a constant string, or every dynamic part is shell-quoted."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.Name):
        return node.id in quoted
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _fixed_or_quoted(node.left, quoted) and _fixed_or_quoted(node.right, quoted)
    if isinstance(node, ast.JoinedStr):
        return all(
            isinstance(part, ast.Constant)
            or (isinstance(part, ast.FormattedValue) and _fixed_or_quoted(part.value, quoted))
            for part in node.values
        )
    if isinstance(node, ast.Tuple):
        return all(_fixed_or_quoted(e, quoted) for e in node.elts)
    if isinstance(node, ast.Call):
        return (_dotted(node.func) or "") in _QUOTERS
    return False


def _is_stdlib_xml(name: str) -> bool:
    """xml.etree / xml.dom / xml.sax names that are not lxml or defusedxml."""
    return "lxml" not in name and not name.startswith("defusedxml")


def _has_safe_loader(kw: dict) -> bool:
    loader = kw.get("Loader")
    name = _dotted(loader) if loader is not None else None
    return bool(name and "safe" in name.lower())


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _dotted(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


# --------------------------------------------------------------------------- JS / TS

_JS_RULES = [
    ("code_injection", re.compile(r"\beval\s*\(")),
    ("code_injection", re.compile(r"\bnew\s+Function\s*\(")),
    (
        # Shell execution only: `child_process.exec(...)` or a bare `exec(...)` imported from it.
        # `regex.exec(str)` (RegExp) and `db.exec(sql)` are method calls on other objects.
        "command_injection",
        re.compile(
            r"\b(?:child_process|childProcess|cp)\.(?:exec|execSync)\s*\("
            r"|(?<![\w.$])(?:exec|execSync)\s*\("
        ),
    ),
    (
        "insecure_deserialization",
        # node-serialize's unserialize() executes functions embedded in the payload
        re.compile(r"\b(yaml|jsYaml)\.load\s*\(|\bserialize\.unserialize\s*\(|\bunserialize\s*\("),
    ),
    ("xss_sink", re.compile(r"\.innerHTML\s*=(?!=)")),
    # libxmljs: parseXml(String)(data, {noent: true}) resolves external entities
    ("xxe", re.compile(r"\bparseXml(?:String)?\s*\(.*\bnoent\s*:\s*true")),
    # libxmljs2: `{ noent: true }` on its own line next to parseXml
    ("xxe", re.compile(r"\bnoent\s*:\s*true\b")),
    # libxml2 bindings: the NOENT parse option substitutes external entities
    ("xxe", re.compile(r"\bXML_PARSE_NOENT\b")),
    ("weak_hash", re.compile(r"\bcreateHash\(\s*['\"](?:md5|sha1)['\"]\s*\)")),
    # Angular: an explicit opt-out of the HTML sanitizer
    ("xss_sink", re.compile(r"\bbypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(")),
    (
        "disabled_tls_verification",
        re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
    ),
]


_JS_STRINGS = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`""")


def _constant_assignment(text: str, end: int) -> bool:
    """True when the statement starting at ``end`` (just after ``innerHTML =``) assigns only string
    literals (no ``+`` of variables, no ``${}`` interpolation): constant markup is not XSS."""
    stop = text.find(";", end)
    stmt = text[end : stop if stop != -1 else end + 1500]
    if "${" in stmt:
        return False
    rest = _JS_STRINGS.sub("", stmt)
    return (
        not rest.replace("+", "").strip()
        and "+" not in rest.strip().strip("+")
        and bool(stmt.strip())
    )


_ESCAPER = re.compile(
    r"^(?:\w+\.)?(?:esc|escape|escapehtml|eschtml|escapeattr|sanitize|sanitizehtml|purify|"
    r"encodeuricomponent|encodeuri|safe)\w*\s*\(",
    re.IGNORECASE,
)
_NUMERIC = re.compile(
    r"^[\d\s+\-*/%().]+$|\bMath\.\w+\(|\.length\b|\.toFixed\(|\.toLocaleString\(|"
    r"\bparseInt\(|\bNumber\(|^\w{1,2}\s*[+\-*/]\s*\d+$|^\w{1,2}$"
)
_STRING_TERNARY = re.compile(r"\?\s*(['\"`])[^'\"`]*\1\s*:\s*(['\"`])[^'\"`]*\2\s*$")
_SOURCEY = re.compile(
    r"\blocation\b|document\.cookie|window\.name|localStorage|sessionStorage|\breq\.|"
    r"\brequest\.|\bparams\b|\bfetch\(|\bXMLHttpRequest\b|\bWebSocket\b|\bawait\b|"
    r"\bresponse\b|\bres\.|\bevent\.|\be\.target|postMessage|\.json\("
)
_CONST_DATA = re.compile(
    r"^[ \t]*const\s+([A-Za-z_]\w*)\s*=[ \t]*[\[{][ \t\n]*[{['\"\d]", re.MULTILINE
)


def _xss_class(text: str, end: int, const_names: set[str]) -> str:
    """Classify the statement after ``innerHTML =``:

    ``skip``    constant markup, or every interpolation is escaped / numeric / a literal choice, or
                it renders the file's own constant data tables (no request-ish source in sight);
    ``opaque``  the value comes from a call (``items.map(card).join('')``): cannot be judged here;
    ``dynamic`` an unescaped, non-constant value is concatenated or interpolated.
    """
    if _constant_assignment(text, end):
        return "skip"
    stop = text.find(";", end)
    stmt = text[end : stop if stop != -1 else end + 1500]
    interps = re.findall(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}", stmt)
    stripped = _JS_STRINGS.sub("", re.sub(r"\$\{(?:[^{}]|\{[^{}]*\})*\}", "", stmt))
    operands = [p.strip() for p in stripped.split("+") if p.strip()]
    has_concat = "+" in stripped
    exprs = [e.strip() for e in interps] + (operands if has_concat else [])
    if not interps and not has_concat:
        # no interpolation and no concatenation: a bare call chain / identifier
        if re.fullmatch(r"\s*[\w$.]+\s*", stmt):
            return "dynamic"  # el.innerHTML = value
        return "opaque"

    def safe(e: str) -> bool:
        return bool(_ESCAPER.match(e) or _NUMERIC.search(e) or _STRING_TERNARY.search(e))

    if all(safe(e) for e in exprs if e not in ("", ",", ")", "(")):
        return "skip"
    if any(re.search(rf"\b{re.escape(n)}\b", stmt) for n in const_names) and not _SOURCEY.search(
        stmt
    ):
        return "skip"
    return "dynamic"


_LITERAL_CALL_ARG = re.compile(r"""\(\s*(?:(['"`])[^'"`$\\]*\1\s*,?\s*)+(?:\{[^{}]*\}\s*)?\)""")


def _js_sinks(relpath: str, text: str) -> list[SinkFinding]:
    findings: list[SinkFinding] = []
    uses_child_process = "child_process" in text
    const_names = set(_CONST_DATA.findall(text))
    offsets: list[int] = []
    pos = 0
    for raw in text.splitlines(keepends=True):
        offsets.append(pos)
        pos += len(raw)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        for category, pattern in _JS_RULES:
            m = pattern.search(line)
            if m and category == "command_injection" and not uses_child_process:
                continue  # no child_process in this file: `exec(` is something else
            xss = (
                _xss_class(text, offsets[lineno - 1] + m.end(), const_names)
                if m and category == "xss_sink"
                else None
            )
            if xss == "dynamic" and not _SOURCEY.search(text):
                xss = "opaque"  # this file reads no input/network: the data arrives from elsewhere
            if xss == "skip":
                continue
            if (
                m
                and category in {"command_injection", "code_injection"}
                and not m.group(0).startswith("vm.")  # vm code strings reach sandbox variables
                and _LITERAL_CALL_ARG.match(line[m.end() - 1 :])
            ):
                continue  # execSync('npm root -g'), new Function('return 1'): a literal, not input
            if m:
                sev, conf, _ = CATEGORY_RISK[category]
                if category == "insecure_deserialization" and m.group(0).startswith(
                    ("yaml", "jsYaml")
                ):
                    sev, conf = "low", 0.3  # js-yaml >= 4 load() is safe; version not visible
                if xss == "opaque":  # value built by a call we cannot see into
                    sev, conf = "low", 0.25
                findings.append(
                    SinkFinding(
                        category, m.group(0).strip(), sev, conf, relpath, lineno, line.strip()[:160]
                    )
                )
    return findings
