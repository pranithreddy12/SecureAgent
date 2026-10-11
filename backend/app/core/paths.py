"""Confine caller-supplied filesystem paths to an allow-list of root directories."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path


class PathNotAllowed(ValueError):
    """The path resolves outside every allowed root."""


def confine_to_roots(path: str, roots: Iterable[str | Path]) -> Path:
    """Resolve ``path`` (symlinks and ``..`` included) and require it under one of ``roots``."""
    resolved = Path(path).expanduser().resolve()
    allowed = [Path(r).resolve() for r in roots]
    for root in allowed:
        if resolved == root or root in resolved.parents:
            return resolved
    raise PathNotAllowed(
        "path is outside the allowed roots" if allowed else "no allowed roots are configured"
    )
