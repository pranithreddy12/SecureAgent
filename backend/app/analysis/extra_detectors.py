"""Detectors for flaw classes the first evaluations showed were missing (ADR-023).

Planted in intentionally vulnerable applications but absent from the scanner: server-side template
injection, XPath injection, NoSQL injection, reflected XSS built into a response string, an unsigned
session cookie, a password stored or compared in plaintext, and (JavaScript) a record fetched by a
request-supplied id with no owner scoping.

Everything here is heuristic and deliberately conservative: each rule names the evidence it
needs and the common safe form that suppresses it. Taint-based rules take an
``is_tainted(node)`` callback so this module does not import the taint engine (which imports it).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Callable

IsTainted = Callable[[ast.AST | None], bool]

# ----------------------------------------------------------------------------- taint-based sinks

_TEMPLATE_CALLS = {"render_template_string", "from_string", "render_string", "renderString"}
_MONGO_RECEIVER = re.compile(r"(?i)(collection|coll\b|mongo|\bdb\.|\bdb\[|users\b|_col\b)")
_MONGO_METHODS = {
    "find",
    "find_one",
    "find_one_and_update",
    "find_one_and_delete",
    "update_one",
    "update_many",
    "delete_one",
    "delete_many",
    "count_documents",
    "aggregate",
    "replace_one",
}
_HTML_RESPONSE_CALLS = {"Response", "make_response", "HTMLResponse", "HttpResponse"}
_TAG = re.compile(r"<\s*/?\s*[A-Za-z][A-Za-z0-9]*")


def _dotted(node: ast.AST | None) -> str:
    parts: list[str] = []
    while isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)):
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def taint_sink(call: ast.Call, is_tainted: IsTainted) -> tuple[str, str] | None:
    """Template / XPath / NoSQL / HTML-response sinks reached by request input."""
    name = _dotted(call.func)
    last = name.rsplit(".", 1)[-1]
    a0 = call.args[0] if call.args else None

    if last in _TEMPLATE_CALLS and is_tainted(a0):
        return "template_injection", name
    if (
        last == "Template"
        and re.search(r"(?i)jinja|mako|template", name)
        and is_tainted(a0)
        and not isinstance(a0, ast.Constant)
    ):
        return "template_injection", name
    # `user_supplied.format(...)`: the *template* is the attacker's, so attribute walks work
    if (
        last == "format"
        and isinstance(call.func, ast.Attribute)
        and not isinstance(call.func.value, ast.Constant)
        and is_tainted(call.func.value)
    ):
        return "template_injection", name

    if last in {"xpath", "XPath"} and is_tainted(a0):
        return "xpath_injection", name

    if last in _MONGO_METHODS and _MONGO_RECEIVER.search(name):
        if isinstance(a0, ast.Dict):
            for key, value in zip(a0.keys, a0.values, strict=False):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "$where"
                    and not isinstance(value, ast.Constant)
                    and is_tainted(value)
                ):
                    return "nosql_injection", name
        elif a0 is not None and is_tainted(a0):
            return "nosql_injection", name  # the whole filter object comes from the request

    if last in _HTML_RESPONSE_CALLS and a0 is not None and _html_with_input(a0, is_tainted):
        return "reflected_xss", name
    return None


def _html_with_input(node: ast.AST, is_tainted: IsTainted) -> bool:
    """A string expression that contains a markup tag literal and an unescaped tainted part."""
    literal = False
    dynamic = False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _TAG.search(sub.value):
            literal = True
    if not literal:
        return False
    if isinstance(node, ast.JoinedStr):
        dynamic = any(
            isinstance(v, ast.FormattedValue) and is_tainted(v.value) for v in node.values
        )
    elif isinstance(node, ast.BinOp):
        parts = [node.left, node.right]
        if isinstance(node.right, ast.Tuple):
            parts = [node.left, *node.right.elts]
        dynamic = any(not isinstance(p, ast.Constant) and is_tainted(p) for p in parts) or any(
            isinstance(p, ast.BinOp) and _html_with_input(p, is_tainted) for p in parts
        )
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and isinstance(node.func.value, ast.Constant):
            dynamic = any(is_tainted(a) for a in [*node.args, *(k.value for k in node.keywords)])
    return dynamic


def return_xss(node: ast.Return, is_tainted: IsTainted) -> bool:
    """``return "<h1>Hello " + name`` in a request handler, with ``name`` request input."""
    return node.value is not None and _html_with_input(node.value, is_tainted)


# ------------------------------------------------------------ JavaScript (line based)

_JS_ID_FETCH = re.compile(
    r"\.(?:find|findOne|findById|findByPk|findAll|findByIdAndUpdate|findOneAndUpdate|"
    r"findByIdAndDelete|destroy|remove|deleteOne|updateOne)\s*\("
)
_JS_REQ_ID = re.compile(r"\breq(?:uest)?\.(?:body|params|query)\.\w*[Ii]d\b|\breq\.params\.id\b")
_JS_BY_ID = re.compile(
    r"\b\w+\.(?:\w*[Bb]yId|get\w*ById|find\w*ById)\s*\(\s*req(?:uest)?\.(?:params|query|body)\.\w+"
)
_JS_MASS_ASSIGN = re.compile(
    r"\bnew\s+[A-Z]\w*\s*\(\s*req(?:uest)?\.body\s*\)"
    r"|\b[A-Z]\w*\.(?:create|insertMany|build)\s*\(\s*req(?:uest)?\.body\s*[,)]"
    r"|\.(?:findOneAndUpdate|findByIdAndUpdate|updateOne|update)\s*\([^)]*,\s*req(?:uest)?\.body\s*[,)]"
    r"|Object\.assign\s*\([^)]*req(?:uest)?\.body"
)
_JS_LOG_SECRET = re.compile(
    r"(?i)\b(?:console\.(?:log|info|debug|warn|error)|logger\.\w+|log\.\w+)\s*\([^)]*"
    r"(?:password|passwd|secret|api[_-]?key|token)\b[^)]*"
)
_JS_ZIPSLIP = re.compile(r"\.extractAllTo\s*\(|\.extract\s*\(\s*\{\s*path\s*:")
_JS_NOSQL_ALIAS_CALL = re.compile(
    r"\.(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|remove|findOneAndUpdate)"
    r"\s*\(\s*(\w+)\s*[,)]"
)
_JS_NOSQL_BODYISH = re.compile(
    r"\.(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|remove)\s*\(\s*"
    r"(?:body|payload|input|params|queryParams|filter\w*)\s*[,)]"
)
_JS_REQ_ISH = r"(?:req(?:uest)?\.(?:body|query|params)|body|query|queryParams|params|payload)"
_JS_SQL_CALL = re.compile(r"\.(?:query|execute|raw)\s*\(|\bdb\.(?:get|all|run|exec)\s*\(")
_JS_SQL_WORD = re.compile(
    r"(?i)\b(?:select\s.+\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b"
)
_JS_STRING_BUILT = re.compile(r"""\$\{|['"`]\s*\+|\+\s*['"`]""")
_JS_OWNER = re.compile(
    r"(?i)\breq\.user\b|req\.session|\buserId\b|\buser\.id\b|currentUser|\bowner\b|tenant|"
    r"organi[sz]ation|\bsession\b|\.userId|\bwhere\b[^\n]*\buser"
)
_JS_FUNCTION_START = re.compile(
    r"^\s*(?:module\.exports|exports\.|async\s+function|function\b|"
    r"(?:router|app)\.(?:get|post|put|patch|delete|use)\b)"
)
_JS_NOSQL_WHERE = re.compile(
    r"""\$where\s*:\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+|[A-Za-z_]\w*\s*[,}])"""
)
_JS_NOSQL_WHOLE = re.compile(
    r"\.(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|remove)\s*\(\s*"
    r"req(?:uest)?\.(?:body|query|params)\s*[,)]"
)
# a Mongo filter field taking a raw request value: {"_id": req.body.id} accepts {"$ne": null}
_JS_NOSQL_FIELD = re.compile(
    r"\.(?:find|findOne|update|updateOne|updateMany|deleteOne|deleteMany|remove)\s*\(\s*"
    r"(?://[^\n]*\n\s*)?\{[^}]*:\s*"
    r"(?:req(?:uest)?\.(?:body|query|params)|body|query)\.\w+"
)
_JS_TEMPLATE = re.compile(
    r"\b(?:ejs\.render|ejs\.compile|pug\.render|pug\.compile|handlebars\.compile|"
    r"Handlebars\.compile|nunjucks\.renderString|_\.template|doT\.template)\s*\("
)
_JS_XPATH = re.compile(r"\bxpath\.(?:select|select1|evaluate|parse)\s*\(|\.selectNodes\s*\(")


def js_findings(lines: list[str], tainted_vars: set[str]) -> list[tuple[str, int, str, str]]:
    """``(type, line, sink, snippet)`` for the JavaScript classes that need a window or no taint."""
    out: list[tuple[str, int, str, str]] = []
    var_res = [re.compile(r"\b" + re.escape(v) + r"\b") for v in tainted_vars]

    def tainted_line(line: str) -> bool:
        return bool(re.search(r"\breq(?:uest)?\.", line)) or any(r.search(line) for r in var_res)

    for i, line in enumerate(lines):
        if len(line) > 4000:
            continue
        lineno = i + 1
        snippet = line.strip()[:160]
        if _JS_NOSQL_WHERE.search(line):
            out.append(("nosql_injection", lineno, "$where", snippet))
        elif _JS_NOSQL_WHOLE.search(line):
            out.append(("nosql_injection", lineno, "find(req.body)", snippet))
        elif re.search(r"(?i)collection|mongo|db\.", line) and _JS_NOSQL_FIELD.search(
            "\n".join(lines[i : i + 3])
        ):
            out.append(("nosql_injection", lineno, "filter field from request", snippet))
        window3 = "\n".join(lines[i : i + 4])
        m = _JS_TEMPLATE.search(line)
        if m and tainted_line(window3):
            out.append(("template_injection", lineno, m.group(0).strip("( "), snippet))
        m = _JS_XPATH.search(line)
        if m and tainted_line(window3):
            out.append(("xpath_injection", lineno, m.group(0).strip("( "), snippet))
        if _JS_MASS_ASSIGN.search(line):
            out.append(("mass_assignment", lineno, "request body into a model", snippet))
        if _JS_LOG_SECRET.search(line) and not re.search(r"(?i)token\s*:\s*['\"]", line):
            out.append(("sensitive_data_in_log", lineno, "logs a secret value", snippet))
        if _JS_ZIPSLIP.search(line):
            out.append(("path_traversal", lineno, "archive extraction (zip slip)", snippet))
        if _JS_BY_ID.search(line):
            start = max(0, i - 8)
            if not _JS_OWNER.search("\n".join(lines[start : i + 3])):
                out.append(("idor", lineno, "record fetched by request id", snippet))
        m = _JS_NOSQL_ALIAS_CALL.search(line)
        if m:
            var = m.group(1)
            before = "\n".join(lines[max(0, i - 8) : i])
            if re.search(
                r"\b" + re.escape(var) + r"\b[^\n]*" + _JS_REQ_ISH + r"\.\w+", before
            ) or re.search(
                r"\b" + re.escape(var) + r"\.\w+\s*=\s*" + _JS_REQ_ISH + r"\.\w+", before
            ):
                out.append(("nosql_injection", lineno, "filter built from request values", snippet))
        elif _JS_NOSQL_BODYISH.search(line):
            out.append(("nosql_injection", lineno, "request object as filter", snippet))
        if _JS_SQL_CALL.search(line):
            window = "\n".join(lines[i : i + 4])
            if _JS_SQL_WORD.search(window) and _JS_STRING_BUILT.search(window):
                out.append(
                    ("sql_injection", lineno, "query built by string concatenation", snippet)
                )
            else:
                m2 = re.search(r"\.(?:query|execute|raw|run|all|get)\s*\(\s*(\w+)\s*[,)]", line)
                if m2:
                    before = "\n".join(lines[max(0, i - 6) : i])
                    pat = r"\b" + re.escape(m2.group(1)) + r"\b\s*=\s*[^;]*"
                    for assign in re.finditer(pat, before):
                        if _JS_SQL_WORD.search(assign.group(0)) and _JS_STRING_BUILT.search(
                            assign.group(0)
                        ):
                            out.append(
                                (
                                    "sql_injection",
                                    lineno,
                                    "query built by string concatenation",
                                    snippet,
                                )
                            )
                            break
        if _JS_ID_FETCH.search(line):
            window = "\n".join(lines[i : i + 5])
            start = i  # look back only to the start of the enclosing handler (<= 8 lines)
            while start > 0 and i - start < 8 and not _JS_FUNCTION_START.match(lines[start]):
                start -= 1
            before = "\n".join(lines[start : i + 1])
            if _JS_REQ_ID.search(window) and not _JS_OWNER.search(window + "\n" + before):
                out.append(
                    ("idor", lineno, _JS_ID_FETCH.search(line).group(0).strip("( ."), snippet)
                )
    return out


# ------------------------------------------------------------ session cookie / passwords

_SESSION_COOKIE_NAME = re.compile(r"(?i)sess|sid\b|auth|login|user|token|account|^cookie$")
_WEAK_ENCODING = re.compile(r"(?i)b64encode|urlsafe_b64encode|json\.dumps|\bstr\(|\.encode\(")
_SIGNED = re.compile(
    r"(?i)sign|serializer|itsdangerous|jwt|encrypt|hmac|secrets\.|token_(?:hex|urlsafe|bytes)|"
    r"uuid|fernet|cipher|session_id|create_access_token|\.dumps\(\s*[a-z_]+\s*,"
)


def insecure_session_cookie(call: ast.Call, assigns: dict[str, list[ast.expr]]) -> str | None:
    """``resp.set_cookie('app_session', base64(json.dumps({'username': u})))``: the cookie *is* the
    session and anyone can write it. Returns a rule description or ``None``."""
    name = _dotted(call.func)
    if name.rsplit(".", 1)[-1] != "set_cookie" or len(call.args) < 1:
        return None
    key = call.args[0]
    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
        return None
    if not _SESSION_COOKIE_NAME.search(key.value):
        return None
    value = (
        call.args[1]
        if len(call.args) > 1
        else next((k.value for k in call.keywords if k.arg == "value"), None)
    )
    if value is None:
        return None
    exprs = [value]
    if isinstance(value, ast.Name):
        exprs = assigns.get(value.id, [])
    if not exprs:
        return None
    text = " ".join(ast.unparse(e) for e in exprs)
    identity_fstring = any(
        isinstance(e, ast.JoinedStr)
        and any(
            isinstance(v, ast.FormattedValue)
            and re.search(r"(?i)user|name|email|admin|role|uid|\bid\b", ast.unparse(v.value))
            for v in e.values
        )
        for e in exprs
    )
    if _SIGNED.search(text) or not (_WEAK_ENCODING.search(text) or identity_fstring):
        return None
    return f"session cookie '{key.value}' is an unsigned, client-writable value"


_PASSWORD_NAME = re.compile(r"(?i)^(?:new_|old_|raw_|plain_|user_)?(?:pass(?:word|wd)?|pwd)$")
_PASSWORD_ATTR = re.compile(r"(?i)^(?:pass(?:word|wd)?|pwd)$")
_HASH_CALL = re.compile(
    r"(?i)hash|bcrypt|argon|pbkdf2|scrypt|crypt|make_password|passlib|digest|sha\d+|md5|"
    r"hexdigest|set_password|generate_password|create_user|create_superuser"
)
_MODEL_CALLEE = re.compile(
    r"^[A-Z]\w*$|(?i:create_?user|add_?user|new_?user|register|signup|insert|save|store)"
)
_DB_METHODS = {"filter_by", "create", "update", "insert", "save", "add", "get_or_create", "execute"}


def plaintext_password(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, str] | None:
    """A password parameter/variable reaches a model constructor, column or INSERT/UPDATE with no
    hashing call anywhere in the function. Returns ``(line, rule)`` for the first such use."""
    names = {
        a.arg
        for a in [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
        if _PASSWORD_NAME.match(a.arg)
    }
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            names.update(
                t.id for t in node.targets if isinstance(t, ast.Name) and _PASSWORD_NAME.match(t.id)
            )
    if not names:
        return None
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _HASH_CALL.search(_dotted(node.func)):
            return None  # the function hashes something: assume it hashes the password

    def uses(node: ast.AST | None) -> bool:
        return node is not None and any(
            isinstance(n, ast.Name) and n.id in names for n in ast.walk(node)
        )

    assigned: dict[str, list[ast.expr]] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    assigned.setdefault(t.id, []).append(node.value)

    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and uses(node.value):
            for t in node.targets:
                if isinstance(t, ast.Attribute) and _PASSWORD_ATTR.match(t.attr):
                    return node.lineno, f"password stored as given: .{t.attr} = ..."
        if isinstance(node, ast.Call):
            callee = _dotted(node.func)
            last = callee.rsplit(".", 1)[-1]
            for kw in node.keywords:
                if kw.arg and _PASSWORD_ATTR.match(kw.arg) and uses(kw.value):
                    if last in _DB_METHODS or _MODEL_CALLEE.search(last):
                        return node.lineno, f"password passed to {last}() without hashing"
            if _MODEL_CALLEE.search(last) and any(
                isinstance(a, ast.Name) and a.id in names for a in node.args
            ):
                if last[:1].isupper() or re.search(r"(?i)user|account|customer|member", last):
                    return node.lineno, f"password passed to {last}() without hashing"
            if last in {"execute", "executemany"} and node.args:
                text = ast.unparse(node.args[0])
                for ref in ast.walk(node.args[0]):  # `q = "INSERT ..."; execute(q % (...))`
                    if isinstance(ref, ast.Name):
                        text += " " + " ".join(ast.unparse(v) for v in assigned.get(ref.id, []))
                if re.search(r"(?i)\b(insert|update)\b", text) and uses(node.args[0]):
                    return node.lineno, "password written by a SQL INSERT/UPDATE without hashing"
    return None
