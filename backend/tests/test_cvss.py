"""CVSS v3 scoring from vectors, and its use for advisories (never invented)."""

from __future__ import annotations

import json

import pytest

from app.analysis.cvss import parse_cvss3
from app.analysis.dependencies import Dependency
from app.analysis.osv import OsvClient

# (vector, published base score) -- values from the FIRST CVSS v3.1 spec / NVD for these vectors.
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 4.8),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize(("vector", "expected"), KNOWN)
def test_known_vectors(vector: str, expected: float) -> None:
    result = parse_cvss3(vector)
    assert result is not None
    assert result.score == expected
    assert result.vector == vector


def test_bands() -> None:
    assert parse_cvss3(KNOWN[0][0]).band == "critical"
    assert parse_cvss3(KNOWN[3][0]).band == "high"
    assert parse_cvss3(KNOWN[5][0]).band == "medium"
    assert parse_cvss3(KNOWN[7][0]).band == "unknown"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "9.8",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown value
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplicate metric
    ],
)
def test_unsupported_or_malformed_vectors_give_no_score(bad: str) -> None:
    assert parse_cvss3(bad) is None


def test_osv_detail_carries_the_computed_score_and_severity_band() -> None:
    dep = Dependency("PyPI", "flask", "0.1", "requirements.txt")
    detail = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "bad",
        "severity": [{"type": "CVSS_V3", "score": KNOWN[0][0]}],
    }

    def fetch(url: str, payload: bytes | None) -> bytes:
        if url.endswith("querybatch"):
            return json.dumps({"results": [{"vulns": [{"id": detail["id"]}]}]}).encode()
        return json.dumps(detail).encode()

    (vuln,) = OsvClient(fetch).query([dep])[dep.key]
    assert vuln.cvss_score == 9.8
    assert vuln.cvss_version == "3.1"
    assert vuln.severity == "critical"  # derived from the vector, not guessed


def test_advisory_without_a_vector_has_no_score() -> None:
    dep = Dependency("PyPI", "flask", "0.1", "requirements.txt")

    def fetch(url: str, payload: bytes | None) -> bytes:
        if url.endswith("querybatch"):
            return json.dumps({"results": [{"vulns": [{"id": "X-1"}]}]}).encode()
        return json.dumps({"id": "X-1", "summary": "s"}).encode()

    (vuln,) = OsvClient(fetch).query([dep])[dep.key]
    assert vuln.cvss_score is None and vuln.severity == "unknown"
