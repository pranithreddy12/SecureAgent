"""Deterministic, verified fix patches for a small set of well-understood findings (ADR-013).

Each fixer is a one-line, local edit with a known-safe replacement (``md5`` -> ``sha256``,
``verify=False`` -> ``verify=True``, ``yaml.load`` -> ``yaml.safe_load`` ...). A patch is only
called **verified** when, applied to a private copy of the file:

1. the result still parses (Python ``ast``), and
2. re-running the scanner shows fewer findings of every fixed type, and
3. no finding type appears that was not there before.

Nothing is executed. Verification proves the *finding* is gone, not that the program's behaviour
is preserved -- each change carries a caveat saying what to check.
"""

from __future__ import annotations

import ast
import difflib
import os
import re
import tempfile
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.schemas.report import ReportFinding

_LOCATION = re.compile(r"^(?P<file>.*):(?P<line>\d+)$")
_SECRET_ASSIGN = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?P<q>['\"])[^'\"\n]*(?P=q)\s*(?P<comment>#.*)?$"
)


@dataclass(frozen=True)
class Change:
    line: int
    finding_type: str
    description: str
    caveat: str
    needs_import_os: bool = False


@dataclass
class FilePatch:
    path: str
    original: str
    patched: str
    changes: list[Change] = field(default_factory=list)
    verified: bool = False
    note: str = ""

    @property
    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.original.splitlines(keepends=True),
                self.patched.splitlines(keepends=True),
                fromfile=f"a/{self.path}",
                tofile=f"b/{self.path}",
            )
        )


# --------------------------------------------------------------------------- fixers
# fixer(line_text) -> (new_text, description, caveat, needs_import_os) | None

_Fixer = Callable[[str], "tuple[str, str, str, bool] | None"]


def _sub_once(pattern: str, repl: str, text: str) -> str | None:
    new, n = re.subn(pattern, repl, text, count=1)
    return new if n else None


def _weak_hash(line: str):
    new = _sub_once(r"\bhashlib\.(?:md5|sha1)\(", "hashlib.sha256(", line)
    if new is None:
        return None
    return (
        new,
        "Use SHA-256 instead of MD5/SHA-1.",
        "Digest values change (stored hashes will not match). For passwords use argon2/bcrypt/"
        "scrypt, not a plain hash.",
        False,
    )


def _tls(line: str):
    new = _sub_once(r"\bverify\s*=\s*False\b", "verify=True", line)
    if new is None:
        return None
    return (
        new,
        "Verify TLS certificates.",
        "Requests to hosts with self-signed or invalid certificates will now fail; supply a CA "
        "bundle (verify='/path/ca.pem') instead of disabling verification.",
        False,
    )


def _yaml(line: str):
    new = _sub_once(r"\byaml\.(?:load|unsafe_load|full_load)\(", "yaml.safe_load(", line)
    if new is None:
        return None
    new = re.sub(r",\s*Loader\s*=\s*[\w.]+", "", new)
    return (
        new,
        "Use yaml.safe_load, which cannot construct arbitrary Python objects.",
        "Documents that relied on custom tags or Python objects will no longer load.",
        False,
    )


def _debug(line: str):
    new = _sub_once(r"(\bDEBUG['\"]?\]?\s*=\s*)True\b", r"\1False", line) or _sub_once(
        r"\bdebug\s*=\s*True\b", "debug=False", line
    )
    if new is None:
        return None
    return (
        new,
        "Disable debug mode.",
        "Enable it per-environment (e.g. from an environment variable), never in production.",
        False,
    )


def _csrf(line: str):
    new = _sub_once(r"(CSRF[A-Z_]*ENABLED['\"]?\]?\s*=\s*)False\b", r"\1True", line)
    if new is None:
        return None
    return (
        new,
        "Re-enable CSRF protection.",
        "State-changing forms/requests must now include the CSRF token.",
        False,
    )


def _jwt(line: str):
    new = _sub_once(r"(['\"]verify_signature['\"]\s*:\s*)False\b", r"\1True", line)
    if new is None:
        return None
    return (
        new,
        "Verify the JWT signature.",
        "Pass the verification key and the allowed algorithms explicitly to jwt.decode().",
        False,
    )


def _secret(line: str):
    m = _SECRET_ASSIGN.match(line)
    if not m:
        return None
    name = m["name"]
    env = name.upper()
    new = f'{m["indent"]}{name} = os.environ["{env}"]'
    if m["comment"]:
        new += f"  {m['comment']}"
    return (
        new,
        f"Read the secret from the {env} environment variable instead of the source code.",
        f"Set {env} in the environment before starting (the app now fails fast if it is missing), "
        "and rotate the exposed value: it is in version control history.",
        True,
    )


FIXERS: dict[str, _Fixer] = {
    "weak_hash": _weak_hash,
    "disabled_tls_verification": _tls,
    "insecure_deserialization": _yaml,  # only yaml.* is rewritten; pickle lines do not match
    "debug_enabled": _debug,
    "csrf_disabled": _csrf,
    "jwt_verification_disabled": _jwt,
    "hardcoded_secret": _secret,
}


# --------------------------------------------------------------------------- engine


def _locate(finding: ReportFinding) -> tuple[str, int] | None:
    m = _LOCATION.match(finding.endpoint or "")
    return (m["file"], int(m["line"])) if m else None


def _insert_import_os(lines: list[str]) -> list[str]:
    if any(re.match(r"^\s*import os\s*(#.*)?$", ln) for ln in lines):
        return lines
    idx = 0
    try:
        tree = ast.parse("".join(lines))
    except SyntaxError:
        return lines
    last_import_end = 0
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last_import_end = node.end_lineno or node.lineno
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and node is tree.body[0]
        ):
            idx = node.end_lineno or node.lineno  # keep the module docstring first
        else:
            break
    idx = max(idx, last_import_end)
    return [*lines[:idx], "import os\n", *lines[idx:]]


def _scan_types(text: str, filename: str) -> Counter[str]:
    with tempfile.TemporaryDirectory(prefix="secureagent-fix-") as tmp:
        (Path(tmp) / Path(filename).name).write_text(text, encoding="utf-8")
        ctx = scan_to_report_context(scan_repo(tmp, check_osv=False))
        return Counter(f.type for f in ctx.findings)


def _verify(patch: FilePatch) -> None:
    fixed = Counter(c.finding_type for c in patch.changes)
    if patch.path.endswith(".py"):
        try:
            ast.parse(patch.patched)
        except SyntaxError as exc:
            patch.note = f"patched file does not parse ({exc.msg}); not applied"
            return
    before = _scan_types(patch.original, patch.path)
    after = _scan_types(patch.patched, patch.path)
    for ftype, n in fixed.items():
        if after[ftype] > before[ftype] - n:
            patch.note = f"re-scan still reports {ftype}; fix did not remove the finding"
            return
    new = [t for t in after if after[t] > before[t]]
    if new:
        patch.note = f"fix introduced new finding type(s): {', '.join(sorted(new))}"
        return
    patch.verified = True
    patch.note = "parses; re-scan shows the findings gone and nothing new"


def suggest_fix_for(root: str, endpoint: str, finding_type: str) -> FilePatch | None:
    """``propose_fixes`` for exactly one finding (by its ``file:line`` and type), for a UI that
    shows one finding at a time -- the web app's "suggested fix" panel, say. ``None`` means either
    the type has no deterministic fixer (most types: see ``FIXERS``) or nothing changed at that
    line. Duck-types the one finding instead of requiring a full ``ReportFinding``."""
    fake = SimpleNamespace(endpoint=endpoint, type=finding_type)
    patches = propose_fixes(root, [fake])
    return patches[0] if patches else None


def propose_fixes(root: str, findings: Sequence[ReportFinding]) -> list[FilePatch]:
    """Build one patch per file covering every fixable finding in it."""
    root_path = Path(root).resolve()
    by_file: dict[str, list[tuple[int, ReportFinding]]] = {}
    for f in findings:
        loc = _locate(f)
        if loc and f.type in FIXERS:
            by_file.setdefault(loc[0], []).append((loc[1], f))

    patches: list[FilePatch] = []
    for rel, items in sorted(by_file.items()):
        path = (root_path / rel).resolve()
        if root_path not in path.parents or path.is_symlink() or not path.is_file():
            continue
        try:
            original = path.read_bytes().decode("utf-8")  # keeps CRLF
        except (OSError, UnicodeDecodeError):
            continue
        lines = original.splitlines(keepends=True)
        changes: list[Change] = []
        needs_os = False
        for lineno, finding in sorted({(ln, f.type): (ln, f) for ln, f in items}.values()):
            if not 0 < lineno <= len(lines):
                continue
            raw = lines[lineno - 1]
            ending = raw[len(raw.rstrip("\r\n")) :]
            result = FIXERS[finding.type](raw.rstrip("\r\n"))
            if result is None:
                continue
            new_text, description, caveat, import_os = result
            if new_text == raw.rstrip("\r\n"):
                continue
            lines[lineno - 1] = new_text + ending
            needs_os = needs_os or import_os
            changes.append(Change(lineno, finding.type, description, caveat, import_os))
        if not changes:
            continue
        if needs_os:
            lines = _insert_import_os(lines)
        patch = FilePatch(rel, original, "".join(lines), changes)
        _verify(patch)
        patches.append(patch)
    return patches


def apply_patches(root: str, patches: Sequence[FilePatch]) -> list[str]:
    """Write verified patches; skip any file that changed since it was analysed."""
    root_path = Path(root).resolve()
    written: list[str] = []
    for p in patches:
        if not p.verified:
            continue
        path = (root_path / p.path).resolve()
        if root_path not in path.parents or path.is_symlink():
            continue
        try:
            if path.read_bytes().decode("utf-8") != p.original:
                continue  # changed since the scan; never overwrite
        except (OSError, UnicodeDecodeError):
            continue
        tmp = path.with_name(path.name + ".secureagent-tmp")
        tmp.write_bytes(p.patched.encode("utf-8"))
        os.replace(tmp, path)
        written.append(p.path)
    return written
