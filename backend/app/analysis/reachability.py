"""Import-level reachability: does first-party code import a vulnerable package at all?

This is the cheapest useful reachability signal, and it is deliberately labelled as such: a
package that is *imported* may still never reach the vulnerable function, and a package that is
*not imported* may still run as a transitive dependency of one that is. So it only orders the
dependency findings; it never hides one.
"""

from __future__ import annotations

import ast
import re

from app.analysis.dependencies import NPM, PYPI, Dependency

# PyPI distribution name -> import name, where they differ (lower-case, '-' and '.' -> '_').
PYPI_IMPORT_NAMES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "python_jose": "jose",
    "pyjwt": "jwt",
    "scikit_learn": "sklearn",
    "opencv_python": "cv2",
    "opencv_python_headless": "cv2",
    "python_dotenv": "dotenv",
    "psycopg2_binary": "psycopg2",
    "psycopg_binary": "psycopg",
    "python_multipart": "multipart",
    "pycryptodome": "Crypto",
    "pycryptodomex": "Cryptodome",
    "protobuf": "google",
    "setuptools": "pkg_resources",
    "msgpack_python": "msgpack",
    "attrs": "attr",
    "dnspython": "dns",
    "python_dateutil": "dateutil",
    "pyopenssl": "OpenSSL",
    "google_generativeai": "google",
    "argon2_cffi": "argon2",
    "djangorestframework": "rest_framework",
}

_JS_IMPORT = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)["']([^"'./][^"']*)["']""",
    re.MULTILINE,
)


def imported_modules(sources: list[tuple[str, str]]) -> tuple[set[str], set[str], bool, bool]:
    """(python top-level modules, npm package names, saw_python, saw_js) imported by the sources."""
    py: set[str] = set()
    js: set[str] = set()
    saw_py = saw_js = False
    for relpath, text in sources:
        if relpath.endswith(".py"):
            saw_py = True
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    py.update(a.name.split(".")[0] for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    py.add(node.module.split(".")[0])
        elif relpath.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            saw_js = True
            for spec in _JS_IMPORT.findall(text):
                parts = spec.split("/")
                js.add("/".join(parts[:2]) if spec.startswith("@") else parts[0])
    return py, js, saw_py, saw_js


def is_imported(dep: Dependency, imports: tuple[set[str], set[str], bool, bool]) -> bool | None:
    """True/False when we can tell, None when the project has no code of that ecosystem."""
    py, js, saw_py, saw_js = imports
    if dep.ecosystem == PYPI:
        if not saw_py:
            return None
        norm = re.sub(r"[-.]", "_", dep.name.lower())
        candidates = {norm, PYPI_IMPORT_NAMES.get(norm, norm)}
        if norm.startswith("python_"):
            candidates.add(norm.removeprefix("python_"))
        lowered = {m.lower() for m in py}
        return any(c.lower() in lowered for c in candidates)
    if dep.ecosystem == NPM:
        if not saw_js:
            return None
        return dep.name in js
    return None
