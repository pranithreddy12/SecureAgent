"""CycloneDX SBOM generation: purl mapping, and a known vulnerability carried into the
``vulnerabilities`` array with its CVSS rating."""

from __future__ import annotations

from app.analysis.dependencies import Dependency
from app.analysis.osv import Vuln
from app.analysis.sbom import to_cyclonedx
from app.analysis.scanner import DependencyFinding, ScanResult


def _result(deps, findings=()) -> ScanResult:
    r = ScanResult(root=".")
    r.dependencies = list(deps)
    r.dependency_findings = list(findings)
    return r


def test_components_and_purls_for_each_ecosystem():
    deps = [
        Dependency("PyPI", "requests", "2.31.0", "requirements.txt"),
        Dependency("npm", "lodash", "4.17.19", "package-lock.json"),
    ]
    doc = to_cyclonedx(_result(deps))
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    purls = {c["purl"] for c in doc["components"]}
    assert purls == {"pkg:pypi/requests@2.31.0", "pkg:npm/lodash@4.17.19"}
    assert "vulnerabilities" not in doc  # none found


def test_known_vulnerability_is_carried_with_its_cvss_rating():
    dep = Dependency("PyPI", "jinja2", "2.10", "requirements.txt")
    vuln = Vuln(
        id="CVE-2019-10906",
        severity="high",
        summary="Sandbox escape",
        url="https://osv.dev/CVE-2019-10906",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_version="3.1",
    )
    finding = DependencyFinding(dependency=dep, vulns=[vuln], severity="high", confidence=0.9)
    doc = to_cyclonedx(_result([dep], [finding]))
    [entry] = doc["vulnerabilities"]
    assert entry["id"] == "CVE-2019-10906"
    assert entry["affects"] == [{"ref": "PyPI:jinja2@2.10"}]
    assert entry["ratings"][0]["score"] == 8.1
    assert entry["ratings"][0]["method"] == "CVSSv3.1"
