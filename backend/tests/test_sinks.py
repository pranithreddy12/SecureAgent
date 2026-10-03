"""Tests for the dangerous-sink detectors (batch #1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.analysis.sinks import scan_sinks
from app.models.enums import FindingStatus
from app.reports.renderer import render_html


def cats(src: str, name: str = "m.py") -> set[str]:
    return {f.category for f in scan_sinks(name, src)}


def test_insecure_deserialization() -> None:
    assert "insecure_deserialization" in cats("import pickle\npickle.loads(data)\n")
    assert "insecure_deserialization" in cats("import yaml\nyaml.load(s)\n")
    assert "insecure_deserialization" in cats("import marshal\nmarshal.loads(b)\n")


def test_safe_deserialization_not_flagged() -> None:
    assert "insecure_deserialization" not in cats("import yaml\nyaml.safe_load(s)\n")
    assert "insecure_deserialization" not in cats(
        "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"
    )


def test_code_and_command_execution() -> None:
    assert "code_injection" in cats("eval(user_input)\n")
    assert "code_injection" in cats("exec(code)\n")
    assert "command_injection" in cats("import os\nos.system(cmd)\n")
    assert "command_injection" in cats("import subprocess\nsubprocess.run(cmd, shell=True)\n")


def test_safe_subprocess_not_flagged() -> None:
    assert "command_injection" not in cats("import subprocess\nsubprocess.run(['ls', '-l'])\n")


def test_weak_hash_but_not_strong() -> None:
    assert "weak_hash" in cats("import hashlib\nhashlib.md5(pw).hexdigest()\n")
    assert "weak_hash" in cats("import hashlib\nhashlib.sha1(x)\n")
    assert "weak_hash" not in cats("import hashlib\nhashlib.sha256(x)\n")


def test_disabled_tls_verification() -> None:
    assert "disabled_tls_verification" in cats("import requests\nrequests.get(u, verify=False)\n")
    assert "disabled_tls_verification" not in cats(
        "import requests\nrequests.get(u, verify=True)\n"
    )


def test_insecure_temp_and_xxe() -> None:
    assert "insecure_temp_file" in cats("import tempfile\ntempfile.mktemp()\n")
    assert "xxe" in cats("import xml.etree.ElementTree as ET\nET.parse(path)\n")


def test_syntax_error_file_safe() -> None:
    assert scan_sinks("broken.py", "def (:\n") == []


def test_js_sinks() -> None:
    assert "code_injection" in cats("eval(x)\n", "a.js")
    assert "command_injection" in cats("child_process.exec(cmd)\n", "a.js")
    assert "xss_sink" in cats("el.innerHTML = userInput\n", "a.js")


def test_severity_and_status_mapping(tmp_path: Path) -> None:
    (tmp_path / "danger.py").write_text(
        "import pickle, hashlib, requests\n"
        "pickle.loads(x)\n"  # suspicious (needs input reachability)
        "hashlib.md5(pw)\n"  # likely (definite weak crypto)
        "requests.get(u, verify=False)\n",  # likely
        encoding="utf-8",
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    assert len(result.sink_findings) == 3
    ctx = scan_to_report_context(result)
    by_type = {f.type: f for f in ctx.findings}
    assert by_type["insecure_deserialization"].status is FindingStatus.SUSPICIOUS
    assert by_type["weak_hash"].status is FindingStatus.LIKELY
    assert by_type["disabled_tls_verification"].status is FindingStatus.LIKELY
    # Never confirmed by static analysis alone.
    assert all(f.status is not FindingStatus.CONFIRMED for f in ctx.findings)


def test_sinks_in_report_html(tmp_path: Path) -> None:
    (tmp_path / "danger.py").write_text("import pickle\npickle.loads(x)\n", encoding="utf-8")
    html = render_html(scan_to_report_context(scan_repo(str(tmp_path), check_osv=False)))
    assert "CWE-502" in html
    assert "Software and Data Integrity Failures" in html


@pytest.mark.parametrize("safe", ["json.loads(x)", "data = {}", "hashlib.sha256(x)"])
def test_benign_code_not_flagged(safe: str) -> None:
    assert scan_sinks("a.py", f"import json, hashlib\n{safe}\n") == []
