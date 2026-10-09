"""Path excludes, .secureagentignore, inline `secureagent: ignore`, and the secret false-positive
fixes. Suppression must always be visible in the output (never silent)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analysis import secrets
from app.analysis.ingest import is_excluded, load_ignore_file
from app.analysis.scanner import scan_repo
from app.cli import main

VULN = (
    "from flask import request\nimport os\n"
    "@app.route('/ping')\n"
    "def ping():\n"
    "    os.system(request.args.get('h'))\n"
)


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# --------------------------------------------------------------- pattern matching


@pytest.mark.parametrize(
    ("relpath", "pattern", "expected"),
    [
        ("backend/tests/test_a.py", "backend/tests/", True),  # directory tree
        ("backend/tests/sub/test_a.py", "backend/tests/*", True),  # * crosses '/'
        ("a/b/vendor.min.js", "*.min.js", True),  # basename glob
        ("src/test_utils.py", "test_*.py", True),
        ("deep/fixtures/x.py", "fixtures/", True),  # directory anywhere in the tree
        ("src/app.py", "backend/tests/", False),
        ("src/app.py", "*.min.js", False),
        ("src/attests/x.py", "tests/", False),  # 'tests/' must not match 'attests/'
    ],
)
def test_is_excluded(relpath: str, pattern: str, expected: bool) -> None:
    assert is_excluded(relpath, [pattern]) is expected


def test_ignore_file_parsing(tmp_path: Path) -> None:
    write(tmp_path, ".secureagentignore", "# comment\n\ntests/\n  *.min.js  \n")
    assert load_ignore_file(tmp_path) == ["tests/", "*.min.js"]


def test_missing_ignore_file_is_empty(tmp_path: Path) -> None:
    assert load_ignore_file(tmp_path) == []


# --------------------------------------------------------------- scanning


def test_exclude_skips_files_and_counts_them(tmp_path: Path) -> None:
    write(tmp_path, "app.py", VULN)
    write(tmp_path, "tests/test_app.py", VULN)
    result = scan_repo(str(tmp_path), check_osv=False, exclude=["tests/"])
    assert result.stats.excluded == 1
    assert {f.relpath for f in result.taint_findings} == {"app.py"}


def test_secureagentignore_file_is_applied(tmp_path: Path) -> None:
    write(tmp_path, "app.py", VULN)
    write(tmp_path, "legacy/old.py", VULN)
    write(tmp_path, ".secureagentignore", "legacy/\n")
    result = scan_repo(str(tmp_path), check_osv=False)
    assert result.stats.excluded == 1
    assert all(f.relpath == "app.py" for f in result.taint_findings)


def test_inline_ignore_hides_only_that_line_and_is_counted(tmp_path: Path) -> None:
    src = (
        "from flask import request\nimport os, hashlib\n"
        "@app.route('/ping')\n"
        "def ping():\n"
        "    os.system(request.args.get('h'))  # secureagent: ignore  (reviewed)\n"
        "    return hashlib.md5(b'x').hexdigest()\n"  # a different line: must still be reported
    )
    write(tmp_path, "app.py", src)
    result = scan_repo(str(tmp_path), check_osv=False)
    assert not result.taint_findings  # the marked line
    assert any(f.category == "weak_hash" for f in result.sink_findings)  # unmarked line survives
    assert result.inline_ignored >= 1  # suppression is counted, not silent


def test_inline_ignore_works_for_taint_reported_in_another_file(tmp_path: Path) -> None:
    write(
        tmp_path,
        "views.py",
        "from flask import request\nfrom helper import run\n"
        "@app.route('/x')\ndef h():\n    run(request.args.get('c'))\n",
    )
    write(
        tmp_path,
        "helper.py",
        "import os\ndef run(c):\n    os.system(c)  # secureagent: ignore\n",
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    assert not [f for f in result.taint_findings if f.relpath == "helper.py"]


def test_inline_ignore_applies_to_route_findings_and_javascript(tmp_path: Path) -> None:
    write(
        tmp_path,
        "server.js",
        "app.post('/admin/reset', h); // secureagent:ignore public by design\n",
    )
    result = scan_repo(str(tmp_path), check_osv=False)
    assert not result.route_findings and result.inline_ignored >= 1


def test_ignore_marker_is_case_insensitive(tmp_path: Path) -> None:
    write(tmp_path, "c.py", "DEBUG = True  # SecureAgent: IGNORE\n")
    assert not scan_repo(str(tmp_path), check_osv=False).misconfig_findings


# --------------------------------------------------------------- CLI visibility


def test_cli_exclude_flag_and_text_notes(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    write(tmp_path, "app.py", "DEBUG = True  # secureagent: ignore\n")
    write(tmp_path, "tests/t.py", VULN)
    main(["scan", str(tmp_path), "--no-osv", "--no-color", "--exclude", "tests/"])
    out = capsys.readouterr().out
    assert "1 file(s) excluded" in out
    assert "hidden by inline `secureagent: ignore`" in out


def test_cli_json_reports_suppression_counts(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    write(tmp_path, "app.py", "DEBUG = True  # secureagent: ignore\n")
    write(tmp_path, "tests/t.py", VULN)
    main(["scan", str(tmp_path), "--no-osv", "--format", "json", "--exclude", "tests/"])
    stats = json.loads(capsys.readouterr().out)["stats"]
    assert stats["excluded_files"] == 1 and stats["inline_ignored_findings"] == 1


def test_exit_code_ignores_suppressed_findings(tmp_path: Path) -> None:
    write(tmp_path, "app.py", "DEBUG = True  # secureagent: ignore\n")
    assert main(["scan", str(tmp_path), "--no-osv", "--no-color"]) == 0


# --------------------------------------------------------------- false-positive fixes


@pytest.mark.parametrize(
    "line",
    [
        'GH_TOKEN="{FAKE_TOKEN}"',  # format/f-string placeholder, not a secret
        'api_key = "{api_key}"',
        'const o = { credentials: "same-origin" }',  # fetch option, not a credential
        'token_type = "bearer"',
        'credentials = "include"',
    ],
)
def test_option_values_and_placeholders_are_not_secrets(line: str) -> None:
    assert secrets.scan_text("a.py", line + "\n") == []


def test_real_looking_credential_is_still_reported() -> None:
    found = secrets.scan_text("a.py", 'DB_PASSWORD = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"\n')
    assert found and found[0].rule.startswith("Hardcoded credential")
