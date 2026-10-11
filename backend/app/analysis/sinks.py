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
    "xml_entity_expansion": (
        "CWE-776",
        "A05:2021 Security Misconfiguration",
        "The standard-library XML parser does not load external entities but can be exhausted by "
        "entity expansion; use defusedxml when parsing untrusted XML.",
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
    visitor = _SinkVisitor(relpath, lines, _collect_aliases(tree))
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
        self.findings: list[SinkFinding] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802 (ast API)
        outer = self.quoted
        self.quoted = _quoted_names(node)  # scoped: another function may reuse the name
        self.generic_visit(node)
        self.quoted = outer

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

        # Weak hashing
        if last in {"md5", "sha1"} and ("hashlib" in name or name == last):
            self._add("weak_hash", name, node.lineno)

        # Insecure temp file
        if name.endswith("tempfile.mktemp") or (last == "mktemp" and "tempfile" in name):
            self._add("insecure_temp_file", name, node.lineno)

        # XXE-prone XML parsing
        if last in {"parse", "fromstring", "parseString"} and re.search(
            r"(?:etree|ElementTree|minidom|expat|sax|lxml)", name
        ):
            # The standard-library parsers do not fetch external entities; they remain open to
            # entity-expansion DoS. lxml resolves entities unless configured not to.
            self._add("xml_entity_expansion" if _is_stdlib_xml(name) else "xxe", name, node.lineno)

        self.generic_visit(node)


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
    ("insecure_deserialization", re.compile(r"\b(yaml|jsYaml)\.load\s*\(")),
    ("xss_sink", re.compile(r"\.innerHTML\s*=")),
    (
        "disabled_tls_verification",
        re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED"),
    ),
]


def _js_sinks(relpath: str, text: str) -> list[SinkFinding]:
    findings: list[SinkFinding] = []
    uses_child_process = "child_process" in text
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        for category, pattern in _JS_RULES:
            m = pattern.search(line)
            if m and category == "command_injection" and not uses_child_process:
                continue  # no child_process in this file: `exec(` is something else
            if m:
                sev, conf, _ = CATEGORY_RISK[category]
                findings.append(
                    SinkFinding(
                        category, m.group(0).strip(), sev, conf, relpath, lineno, line.strip()[:160]
                    )
                )
    return findings
