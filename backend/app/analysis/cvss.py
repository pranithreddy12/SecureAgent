"""CVSS v3.x base-score calculation from a vector string.

Advisories (OSV) usually publish a CVSS *vector*, not a score. The base score is a pure function of
the vector (FIRST CVSS v3.1 specification, section 7), so it can be computed deterministically --
nothing here estimates or invents a score. Unsupported or malformed vectors (CVSS v2, v4, garbage)
return ``None`` and the report keeps saying "CVSS not determined".

v3.0 vectors are scored with the v3.1 round-up rule; the two differ by at most 0.1 in rare cases.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_VECTOR = re.compile(r"^CVSS:3\.[01]/(?:[A-Z]+:[A-Z]/?)+$")


@dataclass(frozen=True)
class CvssResult:
    score: float
    vector: str
    version: str  # "3.0" | "3.1"

    @property
    def band(self) -> str:
        if self.score >= 9.0:
            return "critical"
        if self.score >= 7.0:
            return "high"
        if self.score >= 4.0:
            return "medium"
        return "low" if self.score > 0 else "unknown"


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest one-decimal number >= value, robust to float error."""
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def parse_cvss3(vector: str) -> CvssResult | None:
    vector = (vector or "").strip()
    if not _VECTOR.match(vector):
        return None
    parts = vector.split("/")
    version = parts[0].split(":")[1]
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition(":")
        if key in metrics:
            return None  # duplicate metric: malformed
        metrics[key] = val
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None  # missing or unknown metric value

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return CvssResult(score=score, vector=vector, version=version)
