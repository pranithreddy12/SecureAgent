"""Security logging & monitoring checks (OWASP A09).

Two concrete, low-false-positive static signals:
- **Sensitive data in logs** (CWE-532): a logging/print call whose argument references a
  secret-named value (password, token, api_key, ...). Logged secrets leak into log
  aggregators and backups.
- **Swallowed exceptions** (CWE-778): an `except` block that only does `pass`/`...`,
  silently discarding errors so failures are never logged or monitored.

Python AST only (deterministic). Findings report as "likely" — the pattern is present
in the source; whether the data is truly sensitive at runtime is for the reviewer.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

CATEGORY = {
    "sensitive_data_in_log": (
        "CWE-532",
        "A09:2021 Security Logging and Monitoring Failures",
        "Do not log secrets or credentials; mask or omit them.",
        "medium",
        0.6,
    ),
    "swallowed_exception": (
        "CWE-778",
        "A09:2021 Security Logging and Monitoring Failures",
        "Log or handle exceptions; do not silently swallow them.",
        "low",
        0.6,
    ),
}

LOG_METHODS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|ssn|social_security|credit_card|card_number|cvv|authorization|"
    r"session_id|refresh_token|client_secret)"
)


@dataclass(frozen=True)
class LoggingFinding:
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
        return f"Logging failure: {self.rule}"


def scan_logging(relpath: str, text: str) -> list[LoggingFinding]:
    if not relpath.endswith(".py"):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    lines = text.splitlines()
    out: list[LoggingFinding] = []

    def snippet(line: int) -> str:
        return lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""

    def add(category: str, rule: str, line: int) -> None:
        sev, conf = CATEGORY[category][3], CATEGORY[category][4]
        out.append(LoggingFinding(category, rule, sev, conf, relpath, line, snippet(line)))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_log_call(node):
            sens = _sensitive_arg(node)
            if sens:
                add("sensitive_data_in_log", f"logs sensitive value '{sens}'", node.lineno)
        elif isinstance(node, ast.Try):
            body_lines = (
                lines[node.body[0].lineno - 1 : node.body[-1].end_lineno] if node.body else []
            )
            body = " ".join(body_lines)
            relevant = bool(_SECURITY_CALL.search(body))
            for handler in node.handlers:
                if _is_swallowed(handler) and not _is_deliberate(handler, lines):
                    rule = "except block only does pass/..." + (
                        " around a security-relevant operation" if relevant else ""
                    )
                    add("swallowed_exception", rule, handler.lineno)

    return out


_DELIBERATE_COMMENT = re.compile(
    r"(?i)noqa|best[- ]effort|fall ?back|optional|non-?fatal|expected|intentional|deliberate|"
    r"cleanup|harmless|not critical|ignore[sd]?\b|may fail|can fail|safe to"
)


# A swallowed exception matters when what it hides is a security decision; around ordinary
# best-effort work (cleanup, optional lookups, UI setup) it is noise (0 of 9 held-out samples).
_SECURITY_CALL = re.compile(
    r"(?i)verify|decode|authen|authoriz|permission|token|signature|decrypt|validat|csrf|jwt|"
    r"password|credential|sanitiz|check_access|login|acl\b"
)


def _is_deliberate(handler: ast.ExceptHandler, lines: list[str]) -> bool:
    """A narrow handler (``except ValueError: pass``) is ordinary control flow, and a handler the
    author commented (``# best effort``, ``# noqa: BLE001 - reason``) is a recorded decision."""
    typ = _dotted(handler.type) if handler.type is not None else None
    if typ is not None and typ.rsplit(".", 1)[-1] not in {"Exception", "BaseException"}:
        return True
    if isinstance(handler.type, ast.Tuple):  # except (A, B): pass -- still narrow
        return True
    for lineno in {handler.lineno, handler.body[0].lineno if handler.body else handler.lineno}:
        if 0 < lineno <= len(lines) and "#" in lines[lineno - 1]:
            if _DELIBERATE_COMMENT.search(lines[lineno - 1].split("#", 1)[1]):
                return True
    return False


def _is_log_call(call: ast.Call) -> bool:
    name = _dotted(call.func) or ""
    last = name.rsplit(".", 1)[-1]
    if name == "print" or name.endswith(".print"):
        return True
    return last in LOG_METHODS and "log" in name.lower()


def _sensitive_arg(call: ast.Call) -> str | None:
    for arg in [*call.args, *(kw.value for kw in call.keywords)]:
        for sub in ast.walk(arg):
            name = None
            if isinstance(sub, ast.Name):
                name = sub.id
            elif isinstance(sub, ast.Attribute):
                name = sub.attr
            if name and SENSITIVE.search(name):
                return name
    return None


def _is_swallowed(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return False
    for stmt in handler.body:
        if isinstance(stmt, ast.Pass):
            continue
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and (stmt.value.value is Ellipsis)
        ):
            continue
        return False  # any real statement (log/raise/return/...) means it is handled
    return True


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None
