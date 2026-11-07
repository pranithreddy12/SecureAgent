"""Supply-chain checks on the packages a project *declares*: typosquats and names that do not
exist on the public registry (an AI-hallucinated name, a typo, or a private package).

* Typosquat check: offline, deterministic. A declared name one edit away from a very popular
  package (and not itself that popular package) is suspicious.
* Registry check: online, opt-in through the same switch as the OSV lookup. A 404 from PyPI/npm
  means the name is unclaimed, so anyone could publish malware under it ("slopsquatting"). A
  private registry also produces a 404, so the finding is "suspicious", never "likely".

Malicious packages that *are* published are caught through OSV's ``MAL-`` advisories (see
``scanner._run_osv``), not here.
"""

from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from app.analysis.dependencies import NPM, PYPI

POPULAR = {
    PYPI: {
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "django",
        "flask",
        "fastapi",
        "boto3",
        "botocore",
        "setuptools",
        "python-dateutil",
        "pyyaml",
        "cryptography",
        "pydantic",
        "jinja2",
        "sqlalchemy",
        "pytest",
        "matplotlib",
        "scipy",
        "pillow",
        "beautifulsoup4",
        "selenium",
        "tensorflow",
        "torch",
        "scikit-learn",
        "openai",
        "anthropic",
        "langchain",
        "httpx",
        "aiohttp",
        "celery",
        "redis",
        "psycopg2",
        "pymongo",
        "werkzeug",
        "click",
        "colorama",
        "certifi",
        "charset-normalizer",
        "packaging",
        "uvicorn",
        "gunicorn",
        "paramiko",
        "pyjwt",
        "docker",
        "kubernetes",
        "google-auth",
        "protobuf",
        "grpcio",
        "transformers",
        "lxml",
        "rich",
        "tqdm",
        "attrs",
        "markupsafe",
        "jsonschema",
        "websockets",
        "pymysql",
        "bcrypt",
        "passlib",
        "alembic",
        "starlette",
        "mistralai",
    },
    NPM: {
        "react",
        "react-dom",
        "express",
        "lodash",
        "axios",
        "next",
        "typescript",
        "webpack",
        "moment",
        "chalk",
        "commander",
        "debug",
        "dotenv",
        "jsonwebtoken",
        "mongoose",
        "body-parser",
        "cors",
        "uuid",
        "yargs",
        "request",
        "async",
        "bluebird",
        "underscore",
        "jquery",
        "socket.io",
        "eslint",
        "prettier",
        "nodemon",
        "mysql",
        "mysql2",
        "sequelize",
        "redis",
        "cross-env",
        "rimraf",
        "minimist",
        "semver",
        "colors",
        "color",
        "inquirer",
        "openai",
        "vite",
        "jest",
        "mocha",
        "tailwindcss",
        "bcrypt",
        "bcryptjs",
        "passport",
        "helmet",
        "multer",
        "node-fetch",
        "puppeteer",
        "sharp",
        "nodemailer",
        "express-session",
        "cookie-parser",
        "graphql",
        "prisma",
        "zod",
        "classnames",
        "styled-components",
    },
}

Fetch = Callable[[str], int]  # url -> HTTP status code


@dataclass(frozen=True)
class DeclaredPackage:
    ecosystem: str
    name: str
    relpath: str
    line: int


def _norm(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if ecosystem == PYPI else name.lower()


def _typo_of(name: str, popular: str) -> bool:
    """``name`` is ``popular`` with one *typing slip*: two adjacent letters swapped (reqeusts), a
    letter doubled (requestss) or a letter dropped (reqests).

    Substitutions and arbitrary insertions are deliberately not counted: on real projects they
    mostly hit legitimate neighbours (scapy/scipy, djongo/django, grequests/requests -- measured
    on the held-out apps, ADR-046), while the slips above are what typosquatters register."""
    if name == popular:
        return False
    if len(name) == len(popular):
        diff = [i for i in range(len(name)) if name[i] != popular[i]]
        return (
            len(diff) == 2
            and diff[1] == diff[0] + 1
            and name[diff[0]] == popular[diff[1]]
            and name[diff[1]] == popular[diff[0]]
        )
    if len(name) == len(popular) + 1:  # doubled letter
        i = next((k for k in range(len(popular)) if name[k] != popular[k]), len(popular))
        return name[i + 1 :] == popular[i:] and i > 0 and name[i] == name[i - 1]
    if len(name) == len(popular) - 1:  # dropped letter (not the first one)
        i = next((k for k in range(len(name)) if name[k] != popular[k]), len(name))
        return i > 0 and popular[i + 1 :] == name[i:]
    return False


def typosquat_target(ecosystem: str, name: str) -> str | None:
    """The popular package ``name`` imitates, or None."""
    popular = {_norm(ecosystem, p): p for p in POPULAR.get(ecosystem, ())}
    n = _norm(ecosystem, name)
    if n in popular or len(n) < 5:
        return None
    return next((orig for p, orig in popular.items() if len(p) >= 5 and _typo_of(n, p)), None)


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def declared_packages(relpath: str, text: str) -> list[DeclaredPackage]:
    """Direct dependencies a developer typed: requirements files, pyproject, package.json."""
    base = relpath.rsplit("/", 1)[-1].lower()
    out: list[DeclaredPackage] = []
    if base.startswith("requirements") and base.endswith((".txt", ".in")):
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http://", "https://")):
                continue
            m = _REQ_NAME.match(line)
            if m:
                out.append(DeclaredPackage(PYPI, m.group(1), relpath, i))
    elif base == "pyproject.toml":
        try:
            deps = (tomllib.loads(text).get("project") or {}).get("dependencies") or []
        except tomllib.TOMLDecodeError:
            return []
        for spec in deps:
            m = _REQ_NAME.match(str(spec))
            if m:
                out.append(DeclaredPackage(PYPI, m.group(1), relpath, _line_of(text, m.group(1))))
    elif base == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return []
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                if isinstance(ver, str) and ver.startswith(("file:", "link:", "workspace:", "git")):
                    continue  # local / git sources never come from the registry
                out.append(DeclaredPackage(NPM, name, relpath, _line_of(text, f'"{name}"')))
    return out


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _default_status(url: str) -> int:
    req = urllib.request.Request(  # noqa: S310 - fixed https registry hosts
        url, headers={"User-Agent": "SecureAgent/0.1"}, method="GET"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - fixed https hosts
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


class RegistryClient:
    MAX_CHECKS = 150

    def __init__(self, fetch: Fetch | None = None) -> None:
        self._fetch = fetch or _default_status

    def missing(self, packages: list[DeclaredPackage]) -> list[DeclaredPackage]:
        """Packages the public registry answers 404 for. Network errors are 'unknown', skipped."""
        out: list[DeclaredPackage] = []
        seen: set[tuple[str, str]] = set()
        for pkg in packages:
            key = (pkg.ecosystem, _norm(pkg.ecosystem, pkg.name))
            if key in seen or len(seen) >= self.MAX_CHECKS:
                continue
            seen.add(key)
            if pkg.ecosystem == PYPI:
                url = f"https://pypi.org/pypi/{urllib.parse.quote(pkg.name)}/json"
            elif pkg.ecosystem == NPM:
                url = "https://registry.npmjs.org/" + urllib.parse.quote(pkg.name, safe="@")
            else:
                continue
            try:
                if self._fetch(url) == 404:
                    out.append(pkg)
            except OSError:
                continue
        return out
