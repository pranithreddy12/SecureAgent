"""Convert findings to SARIF 2.1.0 so GitHub code scanning (and other SARIF tools)
can ingest them natively.

GitHub reads ``level`` and the ``security-severity`` property to place findings in the
Security tab, ``partialFingerprints`` to track them across runs, and the driver's
``rules`` for descriptions. One rule is emitted per finding type.
"""

from __future__ import annotations

import re

from app.analysis.baseline import fingerprint
from app.schemas.report import ReportFinding

TOOL_NAME = "SecureAgent"
TOOL_URI = "https://github.com/pranithreddy12/SecureAgent"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "informational": "1.0",
}
_LOC = re.compile(r"^(?P<uri>.*?):(?P<line>\d+)$")


def _split_location(endpoint: str) -> tuple[str, int]:
    m = _LOC.match(endpoint or "")
    if m:
        return m.group("uri").replace("\\", "/"), int(m.group("line"))
    return (endpoint or "").replace("\\", "/") or "unknown", 1


def _help_uri(cwe: str | None) -> str | None:
    if cwe and cwe.startswith("CWE-") and cwe[4:].isdigit():
        return f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
    return None


def _rule_for(finding: ReportFinding) -> dict:
    name = finding.type.replace("_", " ").title().replace(" ", "")
    rule: dict = {
        "id": finding.type,
        "name": name,
        "shortDescription": {"text": finding.type.replace("_", " ").title()},
        "properties": {
            "tags": ["security"] + ([finding.owasp_category] if finding.owasp_category else []),
            "security-severity": _SECURITY_SEVERITY.get(finding.severity.value, "5.5"),
        },
    }
    uri = _help_uri(finding.cwe)
    if uri:
        rule["helpUri"] = uri
    return rule


def _result_for(finding: ReportFinding) -> dict:
    uri, line = _split_location(finding.endpoint)
    message = finding.title
    if finding.description:
        message += f". {finding.description}"
    if finding.remediation:
        message += f" Remediation: {finding.remediation}"
    properties = {"security-severity": _SECURITY_SEVERITY.get(finding.severity.value, "5.5")}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.cve:
        properties["cve"] = finding.cve
    if finding.owasp_category:
        properties["owasp"] = finding.owasp_category
    return {
        "ruleId": finding.type,
        "level": _LEVEL.get(finding.severity.value, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
        "partialFingerprints": {"secureagent/v1": fingerprint(finding)},
        "properties": properties,
    }


def to_sarif(findings: list[ReportFinding], version: str = "0.1.0") -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rules.setdefault(f.type, _rule_for(f))
        results.append(_result_for(f))
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "version": version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
