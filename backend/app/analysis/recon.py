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
}  # fmt: skip

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

    def absorb_file(self, relpath: str, text: str) -> None:
        if relpath.endswith(".py"):
            for m in _PY_IMPORT.finditer(text):
                self._tech(m.group(1) or m.group(2))
            for source, name in _PY_PARAM.findall(text):
                self.parameters.add(f"{_label(source)}:{name}")
        elif relpath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            for m in _JS_IMPORT.finditer(text):
                self._tech(m.group(1) or m.group(2))
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

    def absorb_dependency(self, name: str) -> None:
        self._tech(name.lower())

    def _tech(self, module: str | None) -> None:
        if module and module.lower() in _TECH:
            self.technologies.add(_TECH[module.lower()])

    def summary(self) -> dict[str, list[str]]:
        return {
            "technologies": sorted(self.technologies),
            "parameters": sorted(self.parameters)[:_MAX],
            "outbound_hosts": sorted(self.outbound_hosts)[:_MAX],
            "environment_variables": sorted(self.env_vars)[:_MAX],
        }


def _label(source: str) -> str:
    return {"args": "query", "values": "query/form", "files": "file"}.get(source, source)
