"""Software Bill of Materials: CycloneDX 1.5 JSON, built from the dependency inventory and
known-vulnerability lookup already produced by a scan (``dependencies.py`` / ``osv.py``).

No new scanning happens here -- this is a pure, offline formatter over ``ScanResult``, the same
split the rest of the project uses between analysis and presentation (``sarif.py``, ``reporting.py``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from app.analysis.scanner import ScanResult

_PURL_TYPE = {"PyPI": "pypi", "npm": "npm"}

SECUREAGENT_VERSION = "0.1.0"


def _purl(ecosystem: str, name: str, version: str) -> str:
    kind = _PURL_TYPE.get(ecosystem, ecosystem.lower())
    return f"pkg:{kind}/{name}@{version}"


def _bom_ref(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def to_cyclonedx(result: ScanResult) -> dict[str, Any]:
    """A CycloneDX 1.5 SBOM: one component per declared dependency, plus a ``vulnerabilities``
    entry for each one OSV found a known advisory for (same data the HTML/JSON report shows,
    in the schema a dependency-scanning tool or dashboard expects)."""
    components = [
        {
            "type": "library",
            "bom-ref": _bom_ref(dep.ecosystem, dep.name, dep.version),
            "name": dep.name,
            "version": dep.version,
            "purl": _purl(dep.ecosystem, dep.name, dep.version),
            "properties": [{"name": "secureagent:source-file", "value": dep.relpath}],
        }
        for dep in sorted(result.dependencies, key=lambda d: (d.ecosystem, d.name, d.version))
    ]

    vulnerabilities = []
    for finding in result.dependency_findings:
        ref = _bom_ref(
            finding.dependency.ecosystem, finding.dependency.name, finding.dependency.version
        )
        for vuln in finding.vulns:
            entry: dict[str, Any] = {
                "id": vuln.id,
                "source": {"name": "OSV", "url": vuln.url},
                "description": vuln.summary,
                "affects": [{"ref": ref}],
            }
            if vuln.cvss_score is not None:
                entry["ratings"] = [
                    {
                        "score": vuln.cvss_score,
                        "severity": vuln.severity,
                        "method": f"CVSSv{vuln.cvss_version or '3'}",
                        "vector": vuln.cvss_vector,
                    }
                ]
            else:
                entry["ratings"] = [{"severity": vuln.severity}]
            vulnerabilities.append(entry)

    doc: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [{"vendor": "SecureAgent", "name": "secureagent", "version": SECUREAGENT_VERSION}],
            "component": {"type": "application", "name": "scanned-project"},
        },
        "components": components,
    }
    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities
    return doc
