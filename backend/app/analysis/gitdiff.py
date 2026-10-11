"""Diff mode: which findings are *new* compared with a git ref?

The ref's tree is exported with ``git archive`` into a private temporary directory (nothing is
checked out in your working tree, nothing is executed) and scanned with the same engine. Findings
are compared by their line-independent fingerprint as a multiset, so:

- code that merely moved is not "new";
- a second identical issue in the same file *is* new (multiset, not set).
"""

from __future__ import annotations

import io
import os
import subprocess  # noqa: S404 - fixed git invocations, never shell=True
import tarfile
import tempfile
from collections import Counter
from collections.abc import Sequence

MAX_ARCHIVE_BYTES = 300 * 1024 * 1024


class GitDiffError(RuntimeError):
    """The ref cannot be resolved or exported (not a repository, unknown ref, no git...)."""


def _git(cwd: str, *args: str, binary: bool = False):
    try:
        proc = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607 - resolved via PATH on purpose
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError:
        raise GitDiffError("git is not installed or not on PATH") from None
    except subprocess.TimeoutExpired:
        raise GitDiffError("git timed out") from None
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitDiffError(msg[-1] if msg else f"git {args[0]} failed")
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace").strip()


def export_ref(root: str, ref: str, dest: str) -> str:
    """Export ``ref`` into ``dest``; return the directory corresponding to ``root``."""
    if not ref or ref.startswith("-"):
        raise GitDiffError("invalid git ref")
    top = _git(root, "rev-parse", "--show-toplevel")
    prefix = _git(root, "rev-parse", "--show-prefix")  # path of root inside the repo ("" or "a/b/")
    _git(top, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    data = _git(top, "archive", "--format=tar", ref, "--", prefix or ".", binary=True)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise GitDiffError("the repository snapshot at that ref is too large to scan")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        tar.extractall(dest, filter="data")  # rejects absolute paths, '..', links outside dest
    return os.path.join(dest, prefix.rstrip("/")) if prefix else dest


def base_fingerprints(root: str, ref: str, scan, fingerprint_of, findings_of) -> Counter:
    """Scan ``ref`` and return a multiset of its findings' fingerprints.

    ``scan(path)`` runs the engine, ``findings_of(result)`` returns unified findings and
    ``fingerprint_of(finding)`` identifies one; passed in to keep this module import-light.
    """
    with tempfile.TemporaryDirectory(prefix="secureagent-ref-") as tmp:
        tree = export_ref(root, ref, tmp)
        if not os.path.isdir(tree):
            return Counter()  # the directory did not exist at that ref: everything is new
        return Counter(fingerprint_of(f) for f in findings_of(scan(tree)))


def split_new(items: Sequence[tuple[str, object]], base: Counter):
    """Partition ``(fingerprint, finding)`` pairs into (new, unchanged), consuming the multiset."""
    remaining = Counter(base)
    new, unchanged = [], []
    for fp, f in items:
        if remaining[fp] > 0:
            remaining[fp] -= 1
            unchanged.append((fp, f))
        else:
            new.append((fp, f))
    return new, unchanged
