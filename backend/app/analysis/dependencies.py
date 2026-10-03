"""Parse dependency manifests/lockfiles into a package inventory.

Pure and offline: given a file's text, return the declared (ecosystem, name, version)
packages. Known-vulnerability lookup against OSV is a separate step (``osv.py``).
Supported: requirements.txt, Pipfile.lock, poetry.lock (PyPI); package-lock.json (npm).
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass

PYPI = "PyPI"
NPM = "npm"

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(?P<ver>[^\s;#]+)"
)

LOCKFILE_NAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.in",
    "pipfile.lock",
    "poetry.lock",
    "package-lock.json",
}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    relpath: str

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


def is_lockfile(relpath: str) -> bool:
    base = relpath.rsplit("/", 1)[-1].lower()
    return base in LOCKFILE_NAMES


def parse_dependencies(relpath: str, text: str) -> list[Dependency]:
    base = relpath.rsplit("/", 1)[-1].lower()
    try:
        if base.startswith("requirements") and base.endswith((".txt", ".in")):
            return _parse_requirements(relpath, text)
        if base == "pipfile.lock":
            return _parse_pipfile_lock(relpath, text)
        if base == "poetry.lock":
            return _parse_poetry_lock(relpath, text)
        if base == "package-lock.json":
            return _parse_package_lock(relpath, text)
    except (ValueError, KeyError, tomllib.TOMLDecodeError, json.JSONDecodeError):
        return []
    return []


def _parse_requirements(relpath: str, text: str) -> list[Dependency]:
    deps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            deps.append(Dependency(PYPI, m.group("name").lower(), m.group("ver"), relpath))
    return deps


def _parse_pipfile_lock(relpath: str, text: str) -> list[Dependency]:
    data = json.loads(text)
    deps = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            ver = (info or {}).get("version", "")
            if ver.startswith("=="):
                deps.append(Dependency(PYPI, name.lower(), ver[2:], relpath))
    return deps


def _parse_poetry_lock(relpath: str, text: str) -> list[Dependency]:
    data = tomllib.loads(text)
    return [
        Dependency(PYPI, str(p["name"]).lower(), str(p["version"]), relpath)
        for p in data.get("package", [])
        if p.get("name") and p.get("version")
    ]


def _parse_package_lock(relpath: str, text: str) -> list[Dependency]:
    data = json.loads(text)
    deps: list[Dependency] = []
    seen: set[tuple[str, str]] = set()

    # lockfileVersion 2/3: flat "packages" map keyed by install path.
    for path, info in (data.get("packages") or {}).items():
        if not path or not isinstance(info, dict):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        ver = info.get("version")
        if name and ver and (name, ver) not in seen:
            seen.add((name, ver))
            deps.append(Dependency(NPM, name, ver, relpath))

    # lockfileVersion 1: recursive "dependencies".
    def walk(tree: dict) -> None:
        for name, info in (tree or {}).items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version")
            if ver and (name, ver) not in seen:
                seen.add((name, ver))
                deps.append(Dependency(NPM, name, ver, relpath))
            walk(info.get("dependencies") or {})

    if not deps:
        walk(data.get("dependencies") or {})
    return deps
