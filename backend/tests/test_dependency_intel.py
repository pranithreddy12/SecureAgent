"""KEV/EPSS exploit intelligence, import reachability, malicious packages, and supply-chain name
checks (typosquats, names missing from the public registry). No network: every feed is faked."""

from __future__ import annotations

import json
from pathlib import Path

from app.analysis.dependencies import NPM, PYPI, Dependency
from app.analysis.exploit_intel import EPSS_URL, KEV_URL, ExploitIntelClient, priority
from app.analysis.osv import OsvClient, Vuln
from app.analysis.reachability import imported_modules, is_imported
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.supply_chain import (
    DeclaredPackage,
    RegistryClient,
    declared_packages,
    typosquat_target,
)
from tests.test_dependencies import _fake_osv_fetch


def _intel_fetch(kev: list[str], epss: dict[str, float]):
    def fetch(url: str) -> bytes:
        if url == KEV_URL:
            return json.dumps({"vulnerabilities": [{"cveID": c} for c in kev]}).encode()
        assert url.startswith(EPSS_URL)
        asked = url[len(EPSS_URL) :].split(",")
        rows = [{"cve": c, "epss": str(epss[c])} for c in asked if c in epss]
        return json.dumps({"data": rows}).encode()

    return fetch


def test_intel_lookup_maps_kev_and_epss() -> None:
    client = ExploitIntelClient(_intel_fetch(["CVE-1"], {"CVE-1": 0.9, "CVE-2": 0.002}))
    intel = client.lookup(["CVE-1", "CVE-2", "GHSA-x"])
    assert intel.kev == {"CVE-1"}
    assert intel.epss == {"CVE-1": 0.9, "CVE-2": 0.002}
    assert intel.note is None


def test_intel_failure_degrades_with_a_note() -> None:
    def boom(url: str) -> bytes:
        raise OSError("offline")

    intel = ExploitIntelClient(boom).lookup(["CVE-1"])
    assert intel.kev == set() and intel.epss == {}
    assert "KEV unavailable" in intel.note and "EPSS unavailable" in intel.note


def test_priority_rules() -> None:
    assert priority(True, None, None, "low") == "urgent"
    assert priority(False, 0.3, None, "low") == "high"
    assert priority(False, None, True, "critical") == "high"
    assert priority(False, 0.001, False, "critical") == "low"
    assert priority(False, None, None, "high") == "normal"  # no intel: no demotion


def test_cve_comes_from_an_alias_never_invented() -> None:
    assert Vuln("GHSA-a", "high", "", "", aliases=("CVE-2024-1",)).cve == "CVE-2024-1"
    assert Vuln("GHSA-a", "high", "", "", aliases=("PYSEC-1",)).cve is None
    assert Vuln("MAL-2025-1", "unknown", "", "").malicious


def test_import_reachability() -> None:
    sources = [
        ("app.py", "import yaml\nfrom PIL import Image\nfrom . import local\n"),
        ("web/index.ts", "import axios from 'axios'\nconst x = require('@scope/pkg/sub')\n"),
    ]
    imports = imported_modules(sources)
    assert is_imported(Dependency(PYPI, "pyyaml", "6", "r.txt"), imports) is True
    assert is_imported(Dependency(PYPI, "pillow", "9", "r.txt"), imports) is True
    assert is_imported(Dependency(PYPI, "urllib3", "1", "r.txt"), imports) is False
    assert is_imported(Dependency(NPM, "axios", "1", "p.json"), imports) is True
    assert is_imported(Dependency(NPM, "@scope/pkg", "1", "p.json"), imports) is True
    assert is_imported(Dependency(NPM, "lodash", "1", "p.json"), imports) is False
    py_only = imported_modules([("a.py", "import os\n")])
    assert is_imported(Dependency(NPM, "lodash", "1", "p.json"), py_only) is None


def test_typosquat_detection() -> None:
    assert typosquat_target(PYPI, "reqeusts") == "requests"  # transposition
    assert typosquat_target(PYPI, "requestss") == "requests"  # insertion
    assert typosquat_target(NPM, "expresss") == "express"
    assert typosquat_target(PYPI, "requests") is None  # the real one
    assert typosquat_target(PYPI, "Flask_SQLAlchemy") is None  # unrelated name
    assert typosquat_target(NPM, "mysql2") is None  # both popular
    assert typosquat_target(PYPI, "six") is None  # too short to judge
    assert typosquat_target(PYPI, "reqests") == "requests"  # dropped letter
    # Legitimate neighbours that a plain edit-distance-1 rule flagged on the held-out apps.
    for real in ("grequests", "djongo", "scapy"):
        assert typosquat_target(PYPI, real) is None, real


def test_declared_packages_sources() -> None:
    req = declared_packages("requirements.txt", "# c\nflask>=2\n-r x.txt\nreqeusts==1\n")
    assert [(p.name, p.line) for p in req] == [("flask", 2), ("reqeusts", 4)]
    pkg = declared_packages(
        "package.json",
        json.dumps({"dependencies": {"axios": "^1", "local": "file:../x"}}, indent=2),
    )
    assert [p.name for p in pkg] == ["axios"]
    pyproj = declared_packages("pyproject.toml", '[project]\ndependencies = ["httpx>=0.27"]\n')
    assert [p.name for p in pyproj] == ["httpx"]


def test_registry_404_is_reported_errors_are_skipped() -> None:
    def status(url: str) -> int:
        if "ghost" in url:
            return 404
        if "flaky" in url:
            raise OSError("timeout")
        return 200

    pkgs = [DeclaredPackage(PYPI, n, "requirements.txt", 1) for n in ("ghost-lib", "flaky", "ok")]
    assert [p.name for p in RegistryClient(status).missing(pkgs)] == ["ghost-lib"]


def test_scan_repo_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "requests==2.19.0\nevil-pkg==1.0\nreqeusts==2.0\nghost-lib==0.1\n", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text("import requests\n", encoding="utf-8")
    osv = OsvClient(
        _fake_osv_fetch(
            {("requests", "2.19.0"): ["GHSA-r"], ("evil-pkg", "1.0"): ["MAL-2025-9"]},
            {
                "GHSA-r": {"aliases": ["CVE-2018-18074"], "database_specific": {"severity": "LOW"}},
                "MAL-2025-9": {"summary": "Malicious code in evil-pkg"},
            },
        )
    )
    result = scan_repo(
        str(tmp_path),
        osv_client=osv,
        intel_client=ExploitIntelClient(_intel_fetch(["CVE-2018-18074"], {"CVE-2018-18074": 0.5})),
        registry_client=RegistryClient(lambda url: 404 if "ghost-lib" in url else 200),
    )
    by_name = {f.dependency.name: f for f in result.dependency_findings}
    req = by_name["requests"]
    assert req.kev and req.epss == 0.5 and req.imported is True
    assert req.priority == "urgent" and req.severity == "low"  # severity never escalated
    evil = by_name["evil-pkg"]
    assert evil.malicious and evil.severity == "critical" and evil.priority == "urgent"
    cats = {(f.category, f.evidence) for f in result.misconfig_findings}
    assert ("typosquat_package", "reqeusts") in cats
    assert ("unregistered_package", "ghost-lib") in cats

    ctx = scan_to_report_context(result)
    types = {f.type for f in ctx.findings}
    assert {"malicious_dependency", "vulnerable_dependency", "typosquat_package"} <= types
    squat = next(f for f in ctx.findings if f.type == "typosquat_package")
    assert squat.status.value == "suspicious"


def test_offline_scan_still_flags_typosquats(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("reqeusts==2.0\n", encoding="utf-8")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert [f.category for f in result.misconfig_findings] == ["typosquat_package"]
