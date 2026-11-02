"""Source reconnaissance: build an *application model* from the code (ADR-015).

This is the static counterpart of reconnaissance. It reads source files only and **never contacts
a running system**: live crawling and probing of a target is a different, deferred capability (it
needs the target-authorization gate that is not part of the delivered scope, ADR-014).

The model lists what an auditor would want to know before reading findings: the technologies in
use, every input the application reads (query/body/path/header/cookie names), the hosts the code
calls out to, and the environment variables it depends on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.analysis.validation import is_test_path

# import/require name -> display name
_TECH = {
    "flask": "Flask", "fastapi": "FastAPI", "django": "Django", "starlette": "Starlette",
    "sqlalchemy": "SQLAlchemy", "psycopg2": "PostgreSQL (psycopg2)",
    "asyncpg": "PostgreSQL (asyncpg)", "pymongo": "MongoDB (pymongo)", "redis": "Redis",
    "celery": "Celery", "boto3": "AWS SDK (boto3)",
    "requests": "requests (outbound HTTP)", "httpx": "httpx (outbound HTTP)",
    "aiohttp": "aiohttp", "jwt": "PyJWT", "jose": "python-jose", "yaml": "PyYAML",
    "jinja2": "Jinja2", "pydantic": "Pydantic", "pickle": "pickle (deserialization)",
    "express": "Express", "next": "Next.js", "react": "React", "mongoose": "MongoDB (mongoose)",
    "sequelize": "Sequelize", "axios": "axios (outbound HTTP)", "jsonwebtoken": "jsonwebtoken",
    "pg": "PostgreSQL (pg)", "mysql": "MySQL", "mysql2": "MySQL", "prisma": "Prisma",
    "@nestjs/core": "NestJS", "@prisma/client": "Prisma", "knex": "Knex", "passport": "Passport",
    "bcrypt": "bcrypt", "argon2": "Argon2", "helmet": "helmet", "cors": "cors",
    "slowapi": "slowapi", "flask_limiter": "Flask-Limiter", "django_ratelimit": "django-ratelimit",
    "express-rate-limit": "express-rate-limit", "rate-limiter-flexible": "rate-limiter-flexible",
    "@nestjs/throttler": "NestJS Throttler", "flask_talisman": "Flask-Talisman",
    "secure": "secure", "django_csp": "django-csp", "csp": "csp", "pyotp": "pyotp",
    "django_otp": "django-otp", "otplib": "otplib", "speakeasy": "speakeasy",
    "passlib": "passlib", "flask_wtf": "Flask-WTF", "csurf": "csurf", "stripe": "Stripe",
    "razorpay": "Razorpay", "paypalrestsdk": "PayPal", "braintree": "Braintree",
    "multer": "multer", "python_multipart": "python-multipart", "multipart": "multipart",
    "sentry_sdk": "Sentry", "@sentry/node": "Sentry", "cryptography": "cryptography",
    "nacl": "PyNaCl",
}  # fmt: skip

# module -> protective control it indicates (names are the left column of ADR-045's table)
_CONTROLS = {
    **dict.fromkeys(
        ["slowapi", "flask_limiter", "django_ratelimit", "express-rate-limit",
         "rate-limiter-flexible", "@nestjs/throttler"], "rate_limiting"),
    **dict.fromkeys(["flask_talisman", "secure", "helmet", "django_csp", "csp"], "security_headers"),  # noqa: E501
    **dict.fromkeys(["pyotp", "django_otp", "otplib", "speakeasy"], "mfa"),
    **dict.fromkeys(["bcrypt", "argon2", "passlib"], "password_hashing"),
    **dict.fromkeys(["flask_wtf", "csurf"], "csrf"),
    **dict.fromkeys(["stripe", "razorpay", "paypalrestsdk", "braintree"], "payments"),
    **dict.fromkeys(["multer", "python_multipart", "multipart"], "file_upload"),
    **dict.fromkeys(["sentry_sdk", "@sentry/node"], "error_monitoring"),
    **dict.fromkeys(["cryptography", "nacl"], "encryption"),
}  # fmt: skip

# Data-category vocabulary: a name matches when its snake/camel-split words contain the entry's
# words as a contiguous run. ``pan`` alone is ambiguous (card PAN vs. Indian PAN) (see _categories).
_DATA_WORDS = {
    "pii": ["email", "phone", "mobile", "address", "dob", "birth", "birthdate", "first_name",
            "last_name", "full_name", "gender"],
    "credentials": ["password", "passwd", "pin", "otp", "secret_answer"],
    "payment": ["card_number", "cardnumber", "card_expiry", "cvv", "cvc", "iban", "upi", "upi_id"],
    "financial": ["salary", "income", "account_number", "balance", "ifsc"],
    "health": ["diagnosis", "prescription", "blood_group", "medical", "allergy", "insurance_id"],
    "government_id": ["aadhaar", "pan_number", "ssn", "passport", "national_id", "voter_id"],
    "location": ["latitude", "longitude", "lat", "lng", "geolocation"],
    "biometric": ["fingerprint_template", "face_encoding", "biometric"],
}  # fmt: skip
_DATA_PHRASES = [(tuple(p.split("_")), cat) for cat, words in _DATA_WORDS.items() for p in words]
_NAME_WORDS = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_MAX_FIELDS = 20
_PY_FIELD = re.compile(
    r"^\s*([A-Za-z_]\w*)\s*(?::\s*Mapped\[|=\s*(?:\w+\.)?(?:Column|mapped_column)\("
    r"|=\s*models\.\w*Field\()"
)
_PY_CLASS = re.compile(r"^(\s*)class\s+\w+\s*\(([^)]*)\)")
_FILE_USE = re.compile(r"\brequest\.files\b|\breq\.files?\b")
_URL_PARAMS = frozenset({"url", "uri", "callback", "webhook", "redirect", "next", "target"})
_PY_ANNOTATED = re.compile(r"^\s+([A-Za-z_]\w*)\s*:\s*\S")

_PY_IMPORT = re.compile(
    r"^\s*(?:from\s+([A-Za-z_][\w]*)[\w.]*\s+import|import\s+([A-Za-z_][\w]*))", re.M
)
_JS_IMPORT = re.compile(
    r"""(?:require\(\s*['"]([^'"./][^'"]*)['"]\s*\)|from\s+['"]([^'"./][^'"]*)['"])"""
)
_PY_PARAM = re.compile(
    r"""request\.(args|form|values|json|cookies|headers|files)\s*(?:\.get\(|\[)\s*['"]([\w.-]+)['"]"""
)
_JS_PARAM = re.compile(r"\breq(?:uest)?\.(query|body|params|cookies|headers)\.([A-Za-z_]\w*)")
_JS_PARAM_IDX = re.compile(
    r"""\breq(?:uest)?\.(query|body|params|cookies|headers)\[\s*['"]([\w.-]+)['"]"""
)
_PATH_PARAM = re.compile(r"<(?:[\w:]+:)?(\w+)>|\{(\w+)\}|/:(\w+)")
_HOST = re.compile(r"""['"`]https?://([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(?::\d+)?[/'"`?]""")
_ENV = re.compile(
    r"""(?:os\.environ\s*\[\s*['"]([A-Z0-9_]+)['"]|os\.environ\.get\(\s*['"]([A-Z0-9_]+)['"]"""
    r"""|os\.getenv\(\s*['"]([A-Z0-9_]+)['"]|process\.env\.([A-Z][A-Z0-9_]*))"""
)
_IGNORED_HOSTS = {"localhost", "127.0.0.1", "example.com", "www.w3.org", "schemas.xmlsoap.org"}
_MAX = 200


@dataclass
class ApplicationModel:
    technologies: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)  # "query:q", "json:email", "path:order_id"
    outbound_hosts: set[str] = field(default_factory=set)
    env_vars: set[str] = field(default_factory=set)
    controls: set[str] = field(default_factory=set)  # protective controls whose module is imported
    # category -> {(relpath, line, "json:card_number" | "field:card_number")}, at most 20 each
    data_fields: dict[str, set[tuple[str, int, str]]] = field(default_factory=dict)
    control_files: dict[str, str] = field(default_factory=dict)  # control -> first file using it
    upload_files: set[str] = field(default_factory=set)  # files reading uploaded files
    url_params: set[tuple[str, int, str]] = field(default_factory=set)  # user-supplied URLs

    def absorb_file(self, relpath: str, text: str) -> None:
        code = relpath.endswith((".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
        if code and not is_test_path(relpath):  # fixtures say nothing about the real app's data
            self._absorb_data(relpath, text)
        if relpath.endswith(".py"):
            for m in _PY_IMPORT.finditer(text):
                self._tech(m.group(1) or m.group(2), relpath)
            for source, name in _PY_PARAM.findall(text):
                self.parameters.add(f"{_label(source)}:{name}")
        elif relpath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            for m in _JS_IMPORT.finditer(text):
                self._tech(m.group(1) or m.group(2), relpath)
            for source, name in [*_JS_PARAM.findall(text), *_JS_PARAM_IDX.findall(text)]:
                self.parameters.add(f"{_label(source)}:{name}")
        else:
            return
        for m in _HOST.finditer(text):
            host = m.group(1).lower()
            if host not in _IGNORED_HOSTS and "." in host:
                self.outbound_hosts.add(host)
        for m in _ENV.finditer(text):
            self.env_vars.add(next(g for g in m.groups() if g))

    def absorb_route_path(self, path: str) -> None:
        for groups in _PATH_PARAM.findall(path):
            name = next((g for g in groups if g), None)
            if name:
                self.parameters.add(f"path:{name}")

    def absorb_dependency(self, name: str, relpath: str | None = None) -> None:
        self._tech(name.lower(), relpath)

    def _tech(self, module: str | None, relpath: str | None = None) -> None:
        if not module:
            return
        key = module.lower()
        if key not in _TECH:
            key = key.replace("-", "_")  # dependency names: flask-limiter -> flask_limiter
        if key in _TECH:
            self.technologies.add(_TECH[key])
        if key in _CONTROLS:
            ctl = _CONTROLS[key]
            self.controls.add(ctl)
            if relpath:
                self.control_files[ctl] = min(relpath, self.control_files.get(ctl, relpath))

    def _absorb_data(self, relpath: str, text: str) -> None:
        hits: list[tuple[int, str]] = []  # (line, "json:card_number" | "field:card_number")
        in_model, class_indent = False, 0
        py = relpath.endswith(".py")
        for n, line in enumerate(text.splitlines(), 1):
            if py:
                cls = _PY_CLASS.match(line)
                if cls:
                    in_model, class_indent = "BaseModel" in cls.group(2), len(cls.group(1))
                elif line.strip() and len(line) - len(line.lstrip()) <= class_indent:
                    in_model = False
                m = _PY_FIELD.match(line) or (in_model and _PY_ANNOTATED.match(line))
                if m:
                    hits.append((n, f"field:{m.group(1)}"))
                pairs = _PY_PARAM.findall(line)
            else:
                pairs = [*_JS_PARAM.findall(line), *_JS_PARAM_IDX.findall(line)]
            hits.extend((n, f"{_label(src)}:{name}") for src, name in pairs)
        if _FILE_USE.search(text):
            self.upload_files.add(relpath)
        if not hits:
            return
        names = {h[1].split(":", 1)[1] for h in hits}
        pay_ctx = _imports_payment(text) or any("payment" in _categories(nm, False) for nm in names)
        for n, label in hits:
            name = label.split(":", 1)[1]
            for cat in _categories(name, pay_ctx):
                _keep(self.data_fields.setdefault(cat, set()), (relpath, n, label))
            if name.lower() in _URL_PARAMS and not label.startswith("field:"):
                _keep(self.url_params, (relpath, n, label))

    def summary(self) -> dict[str, list[str]]:
        return {
            "technologies": sorted(self.technologies),
            "parameters": sorted(self.parameters)[:_MAX],
            "outbound_hosts": sorted(self.outbound_hosts)[:_MAX],
            "environment_variables": sorted(self.env_vars)[:_MAX],
            "controls": sorted(self.controls),
            "data_categories": sorted(self.data_fields),
        }


def _label(source: str) -> str:
    return {"args": "query", "values": "query/form", "files": "file"}.get(source, source)


def _categories(name: str, payment_context: bool) -> set[str]:
    """Data categories a field/parameter name suggests (whole-word match on the split name)."""
    words = tuple(w.lower() for w in _NAME_WORDS.findall(name))
    if "pin" in words and words[words.index("pin") + 1 : words.index("pin") + 2] == ("code",):
        words = tuple(w for w in words if w != "pin")  # pin_code is a postal code, not a PIN
    found = set()
    for phrase, cat in _DATA_PHRASES:
        n = len(phrase)
        if any(words[i : i + n] == phrase for i in range(len(words) - n + 1)):
            found.add(cat)
    if "pan" in words and payment_context:
        i = words.index("pan")
        if words[i : i + 2] != ("pan", "number"):
            found.add("payment")
    if "expiry" in words and payment_context:  # token_expiry alone is not card data
        found.add("payment")
    return found


def _imports_payment(text: str) -> bool:
    for m in [*_PY_IMPORT.finditer(text), *_JS_IMPORT.finditer(text)]:
        mod = (m.group(1) or m.group(2) or "").lower()
        if _CONTROLS.get(mod) == "payments":
            return True
    return False


def _keep(bucket: set, item: tuple) -> None:
    bucket.add(item)
    if len(bucket) > _MAX_FIELDS:
        bucket.discard(max(bucket))  # keep the 20 smallest: independent of file order
