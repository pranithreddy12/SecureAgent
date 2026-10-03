"""Tests for dependency parsing and OSV known-vulnerability mapping. No network."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.dependencies import NPM, PYPI, parse_dependencies
from app.analysis.osv import OsvClient, Vuln
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.reports.renderer import render_html

REQUIREMENTS = """
# comment
fastapi==0.115.0
Jinja2==3.1.6
unpinned-pkg>=1.0
-r other.txt
requests==2.31.0 ; python_version >= "3.8"
"""

PACKAGE_LOCK = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "node_modules/lodash": {"version": "4.17.20"},
            "node_modules/express": {"version": "4.18.2"},
        },
    }
)

POETRY_LOCK = """
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"
"""


def test_parse_requirements_pins_only() -> None:
    deps = parse_dependencies("requirements.txt", REQUIREMENTS)
    names = {(d.name, d.version) for d in deps}
    assert ("fastapi", "0.115.0") in names
    assert ("jinja2", "3.1.6") in names
    assert ("requests", "2.31.0") in names
    assert all(d.ecosystem == PYPI for d in deps)
    assert not any(d.name == "unpinned-pkg" for d in deps)  # no == pin


def test_parse_package_lock_v3() -> None:
    deps = parse_dependencies("package-lock.json", PACKAGE_LOCK)
    assert {(d.name, d.version) for d in deps} == {("lodash", "4.17.20"), ("express", "4.18.2")}
    assert all(d.ecosystem == NPM for d in deps)


def test_parse_poetry_lock() -> None:
    deps = parse_dependencies("poetry.lock", POETRY_LOCK)
    assert {(d.name, d.version) for d in deps} == {("requests", "2.31.0"), ("urllib3", "2.0.7")}


def test_malformed_lockfile_returns_empty() -> None:
    assert parse_dependencies("package-lock.json", "{not json") == []


# --- OSV client with an injected fake transport (no real HTTP) ---


def _fake_osv_fetch(querybatch_results: dict, vuln_details: dict):
    def fetch(url: str, payload: bytes | None) -> bytes:
        if url.endswith("/querybatch"):
            queries = json.loads(payload)["queries"]
            results = []
            for q in queries:
                key = (q["package"]["name"], q["version"])
                ids = querybatch_results.get(key, [])
                results.append({"vulns": [{"id": i} for i in ids]})
            return json.dumps({"results": results}).encode()
        vid = url.rsplit("/", 1)[-1]
        return json.dumps(vuln_details.get(vid, {})).encode()

    return fetch


def test_osv_maps_versions_to_advisories() -> None:
    deps = parse_dependencies("requirements.txt", "requests==2.19.0\nsafe-pkg==1.0.0\n")
    fetch = _fake_osv_fetch(
        querybatch_results={("requests", "2.19.0"): ["CVE-2018-18074", "GHSA-xxxx"]},
        vuln_details={
            "CVE-2018-18074": {
                "summary": "Credentials leak on redirect",
                "database_specific": {"severity": "HIGH"},
            },
            "GHSA-xxxx": {"severity": [{"type": "CVSS_V3", "score": "5.0"}]},
        },
    )
    result = OsvClient(fetch=fetch).query(deps)
    vulns = result[(PYPI, "requests", "2.19.0")]
    by_id = {v.id: v for v in vulns}
    assert by_id["CVE-2018-18074"].severity == "high"
    assert by_id["CVE-2018-18074"].cve == "CVE-2018-18074"
    assert by_id["GHSA-xxxx"].severity == "medium"  # CVSS 5.0 -> medium band
    assert by_id["GHSA-xxxx"].cve is None  # GHSA id is not invented as a CVE
    assert (PYPI, "safe-pkg", "1.0.0") not in result  # no advisories -> not reported


def test_scan_repo_with_injected_osv_client(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    fetch = _fake_osv_fetch(
        querybatch_results={("requests", "2.19.0"): ["CVE-2018-18074"]},
        vuln_details={"CVE-2018-18074": {"database_specific": {"severity": "HIGH"}}},
    )
    result = scan_repo(str(tmp_path), osv_client=OsvClient(fetch=fetch))
    assert len(result.dependency_findings) == 1
    f = result.dependency_findings[0]
    assert f.dependency.name == "requests" and f.severity == "high"
    assert any(v.id == "CVE-2018-18074" for v in f.vulns)

    html = render_html(scan_to_report_context(result))
    assert "Vulnerable and Outdated Components" in html
    assert "CVE-2018-18074" in html and "requests" in html


def test_scan_repo_osv_disabled(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert result.dependencies  # inventory still built
    assert result.dependency_findings == []  # but no lookup
    assert result.osv_note and "skipped" in result.osv_note.lower()


def test_osv_network_failure_is_graceful(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")

    def boom(url, payload):
        raise OSError("network down")

    result = scan_repo(str(tmp_path), osv_client=OsvClient(fetch=boom))
    assert result.dependency_findings == []
    assert result.osv_note and "unavailable" in result.osv_note.lower()


def test_vuln_dataclass_cve_property() -> None:
    assert Vuln("CVE-2021-1", "high", "", "").cve == "CVE-2021-1"
    assert Vuln("GHSA-abcd", "high", "", "").cve is None
