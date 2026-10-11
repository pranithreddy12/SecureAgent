"""Rule-based finding validation: false-positive reduction without touching a target (ADR-015).

This is the *Validator* idea, not the live "Safe Validation" agent: it cannot confirm that a flaw
is exploitable (that needs interaction with a running system, which is outside the delivered
scope). It only reclassifies findings that the **location** shows are not production risk, and it
says why. Rules are deterministic and conservative:

- ``test_or_example_code``: the finding sits in test/fixture/example/sample/mock code or a
  ``*.example`` / ``*.sample`` / ``*.template`` file;
- ``development_only_config``: a debug flag in a clearly development-only settings file.

A reclassified finding keeps its severity and evidence but becomes ``informational`` with half its
confidence, and its ``status_reason`` records the rule. Nothing is ever promoted to ``confirmed``
and nothing is deleted. Reclassified findings do not fail ``--fail-on`` gates.
"""

from __future__ import annotations

import re
from collections import Counter

from app.core.enums import FindingStatus
from app.schemas.report import ReportFinding

_TEST_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixtures", "fixture", "examples", "example",
    "samples", "sample", "mocks", "mock", "testdata", "e2e", "cypress",
}  # fmt: skip
_TEST_FILE = re.compile(
    r"(?i)(^test_.*\.py$|.*_test\.py$|.*\.(test|spec)\.[jt]sx?$|.*\.(example|sample|template|dist)$|"
    r"^conftest\.py$)"
)
_DEV_FILE = re.compile(r"(?i)(^|[/\\._-])(dev|development|local|debug)([/\\._-]|$)")
_LOCATION = re.compile(r"^(?P<file>.*):\d+$")

RULE_TEST = "test_or_example_code"
RULE_DEV = "development_only_config"


def _file_of(finding: ReportFinding) -> str:
    m = _LOCATION.match(finding.endpoint or "")
    return (m["file"] if m else finding.endpoint or "").replace("\\", "/")


def _rule_for(finding: ReportFinding) -> str | None:
    path = _file_of(finding)
    parts = path.split("/")
    if any(p.lower() in _TEST_DIRS for p in parts[:-1]) or _TEST_FILE.match(parts[-1]):
        return RULE_TEST
    if finding.type == "debug_enabled" and _DEV_FILE.search(path):
        return RULE_DEV
    return None


def rule_for(finding: ReportFinding) -> str | None:
    """Which validation rule (if any) applies to a finding."""
    return _rule_for(finding)


_REASON = {
    RULE_TEST: "Located in test/fixture/example code, not part of the deployed application.",
    RULE_DEV: "Debug flag in a development-only configuration file; verify production differs.",
}


def validate_findings(findings: list[ReportFinding]) -> tuple[list[ReportFinding], Counter]:
    """Return (findings, {rule: count}). Input order is preserved."""
    applied: Counter = Counter()
    out: list[ReportFinding] = []
    for f in findings:
        rule = _rule_for(f) if f.status is not FindingStatus.FALSE_POSITIVE else None
        if rule is None or f.status is FindingStatus.INFORMATIONAL:
            out.append(f)
            continue
        applied[rule] += 1
        reason = f"{_REASON[rule]} (reclassified from '{f.status.value}' by rule {rule})"
        out.append(
            f.model_copy(
                update={
                    "status": FindingStatus.INFORMATIONAL,
                    "confidence": round(f.confidence * 0.5, 2),
                    "status_reason": reason,
                    "validation_method": (f.validation_method or "static analysis")
                    + f"; rule-based validation: {rule}",
                }
            )
        )
    return out, applied
