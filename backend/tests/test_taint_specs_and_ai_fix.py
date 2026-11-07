"""Project taint specs (IRIS-style, AI-suggested but human-committed) and AI-drafted fixes that
must pass the same verification as the deterministic fixers. No network: transports are faked."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analysis import llm_review as lr
from app.analysis import taint_specs as ts
from app.analysis.fixes import apply_loose_diff, verify_ai_fix
from app.analysis.scanner import scan_repo
from app.cli import main

WRAPPED_APP = """
from flask import Flask
from mylib.http import get_param
from mylib.db import run_sql
from mylib.safe import quote_ident

app = Flask(__name__)

def report():
    name = get_param("name")
    run_sql("SELECT * FROM t WHERE n = '" + name + "'")

def safe_report():
    name = quote_ident(get_param("name"))
    run_sql("SELECT * FROM t WHERE n = '" + name + "'")
"""


def _write(tmp_path: Path, spec: dict | None) -> None:
    (tmp_path / "app.py").write_text(WRAPPED_APP, encoding="utf-8")
    if spec is not None:
        (tmp_path / ts.FILENAME).write_text(json.dumps(spec), encoding="utf-8")


def test_without_a_spec_the_wrapped_flow_is_invisible(tmp_path: Path) -> None:
    _write(tmp_path, None)
    assert scan_repo(str(tmp_path), check_osv=False).taint_findings == []


def test_spec_adds_sources_sinks_and_sanitizers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "sources": ["get_param"],
            "sinks": {"sql_injection": ["run_sql"]},
            "sanitizers": ["quote_ident"],
        },
    )
    found = scan_repo(str(tmp_path), check_osv=False).taint_findings
    assert [(f.vuln_type, f.line) for f in found] == [("sql_injection", 11)]
    assert "[taint spec]" in found[0].sink
    # The spec is scoped to that scan only.
    assert ts.ACTIVE.get() == ts.TaintSpec()


def test_malformed_spec_is_an_error_not_ignored(tmp_path: Path) -> None:
    _write(tmp_path, {"sinks": {"made_up_type": ["x"]}})
    with pytest.raises(ts.TaintSpecError, match="unknown sink type"):
        scan_repo(str(tmp_path), check_osv=False)


def test_candidates_are_names_and_signatures_only() -> None:
    lines = ts.candidates([("app.py", WRAPPED_APP), ("tests/test_x.py", "def test_a(): pass")])
    names = {ts.candidate_name(line) for line in lines}
    assert {"report", "get_param", "run_sql", "quote_ident"} <= names
    assert "test_a" not in names  # test code is not offered
    assert not any("SELECT" in line for line in lines)  # no literal values leave the machine


def test_suggestion_drops_invented_names() -> None:
    lines = ["call get_param  (x2)", "call run_sql  (x2)"]
    text = json.dumps(
        {
            "sources": ["get_param", "request.args"],
            "sinks": {"sql_injection": ["run_sql"], "weird": ["x"]},
            "sanitizers": [],
        }
    )
    spec, dropped = ts.parse_suggestion("Here you go:\n" + text, lines)
    assert spec.sources == {"get_param"} and spec.sinks == {"run_sql": "sql_injection"}
    assert "request.args" in dropped and "weird:x" in dropped


def test_merge_keeps_human_choices() -> None:
    old = ts.TaintSpec(frozenset({"a"}), {"s": "ssrf"}, frozenset())
    new = ts.TaintSpec(frozenset({"b"}), {"s": "sql_injection", "t": "ssrf"}, frozenset({"c"}))
    merged = ts.merge(old, new)
    assert merged.sources == {"a", "b"} and merged.sinks == {"s": "ssrf", "t": "ssrf"}


def _anthropic(text: str):
    return lambda payload, headers: {"content": [{"type": "text", "text": text}]}


def test_specs_command_end_to_end(tmp_path: Path, monkeypatch, capsys) -> None:
    _write(tmp_path, None)
    reply = json.dumps({"sources": ["get_param"], "sinks": {"sql_injection": ["run_sql"]}})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(lr, "http_transport", _anthropic(reply))
    assert main(["specs", str(tmp_path), "--yes", "--write"]) == 0
    spec = ts.load(tmp_path / ts.FILENAME)
    assert spec.sinks == {"run_sql": "sql_injection"}
    assert scan_repo(str(tmp_path), check_osv=False).taint_findings  # now visible


def test_specs_refuses_to_send_without_consent(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path, None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["specs", str(tmp_path)]) == 2


# ----------------------------------------------------------------------------- AI fixes

VULN = """import sqlite3


def find(conn, request):
    name = request.args.get("name")
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()
"""


def test_loose_diff_applies_only_an_unambiguous_hunk() -> None:
    diff = (
        "--- a/x.py\n+++ b/x.py\n@@\n"
        '-    return conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'").fetchall()\n'
        '+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()\n'
    )
    out = apply_loose_diff(VULN, diff)
    assert out is not None and "name = ?" in out and "+ name +" not in out
    assert apply_loose_diff(VULN, "-not in the file\n+x\n") is None
    assert apply_loose_diff("a\nb\na\n", "-a\n+c\n") is None  # matches twice: refuse to guess


def test_ai_fix_is_verified_only_when_the_rescan_agrees(tmp_path: Path) -> None:
    (tmp_path / "db.py").write_text(VULN, encoding="utf-8")
    good = {
        "description": "Bind the parameter.",
        "diff": '-    return conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
        '.fetchall()\n+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))'
        ".fetchall()\n",
        "caveat": "",
    }
    patch = verify_ai_fix(str(tmp_path), "db.py:6", "sql_injection", good)
    assert patch.verified, patch.note

    cosmetic = dict(good, diff="-import sqlite3\n+import sqlite3  # db\n")
    patch = verify_ai_fix(str(tmp_path), "db.py:6", "sql_injection", cosmetic)
    assert not patch.verified and "still reports sql_injection" in patch.note

    broken = dict(good, diff="-import sqlite3\n+import (\n")
    assert "does not parse" in verify_ai_fix(str(tmp_path), "db.py:6", "x", broken).note
    assert "outside" not in verify_ai_fix(str(tmp_path), "../etc.py:1", "x", good).note


def test_fix_ai_command_applies_only_verified(tmp_path: Path, monkeypatch, capsys) -> None:
    (tmp_path / "db.py").write_text(
        VULN.replace("def find(conn, request):", "@app.get('/u')\ndef find(conn, request):"),
        encoding="utf-8",
    )
    reply = json.dumps(
        {
            "description": "Bind the parameter.",
            "diff": '-    return conn.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
            '.fetchall()\n+    return conn.execute("SELECT * FROM users WHERE name = ?", (name,))'
            ".fetchall()\n",
            "caveat": "Check the driver's placeholder style.",
        }
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(lr, "http_transport", _anthropic(reply))
    assert main(["fix", str(tmp_path), "--ai", "--yes", "--apply"]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "1/1 AI patch(es) verified" in out
    assert "name = ?" in (tmp_path / "db.py").read_text(encoding="utf-8")
