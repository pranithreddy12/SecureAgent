"""Finding fingerprints and baseline handling for CI adoption.

A baseline lets a team accept the findings that exist today and fail the build only on
*new* ones. Fingerprints exclude line numbers so moving code around does not churn the
baseline; they stay stable unless the finding's kind, file, or identity changes.
"""

from __future__ import annotations

import hashlib
import json
import re

from app.schemas.report import ReportFinding

_LINE_SUFFIX = re.compile(r":\d+$")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def fingerprint(f: ReportFinding) -> str:
    location = _LINE_SUFFIX.sub("", f.endpoint or "")
    key = "|".join([f.type, location, f.parameter or "", f.title])
    return hashlib.sha1(key.encode("utf-8", "replace")).hexdigest()[:16]  # noqa: S324 - id, not security  # secureagent: ignore


def load_baseline(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return set()
    if isinstance(data, dict):
        return set(data.get("fingerprints", []))
    if isinstance(data, list):
        return set(data)
    return set()


def write_baseline(path: str, fingerprints: list[str]) -> int:
    unique = sorted(set(fingerprints))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"fingerprints": unique}, fh, indent=2)
        fh.write("\n")
    return len(unique)


def fails_threshold(severity: str, threshold: str | None) -> bool:
    """True if a finding at `severity` should fail a build gated at `threshold`."""
    if threshold is None:
        return True
    return SEVERITY_RANK.get(severity, 9) <= SEVERITY_RANK.get(threshold, 9)
