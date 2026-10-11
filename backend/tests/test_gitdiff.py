"""Diff mode: only findings that are new since a git ref."""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # noqa: S404
from pathlib import Path

import pytest

from app.analysis.gitdiff import GitDiffError, export_ref, split_new
from app.cli import main
from app.mcp_server import handle

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=cwd,
        env=ENV,
        check=True,
        capture_output=True,
        text=True,  # noqa: S607
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.py").write_text("import hashlib\nhashlib.md5(b'a')\n", encoding="utf-8")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    return tmp_path


def run_json(repo: Path, capsys, *extra: str) -> dict:
    code = main(["scan", str(repo), "--no-osv", "--format", "json", *extra])
    out = capsys.readouterr().out
    return {"code": code, **json.loads(out)}


def test_only_new_findings_are_reported_and_gate_on_them(repo, capsys):
    # a pre-existing finding is unchanged; add a genuinely new one in a new file
    (repo / "new.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n")
    out = run_json(repo, capsys, "--since", "HEAD", "--fail-on", "low")
    types = {f["type"] for f in out["findings"]}
    assert "weak_hash" not in types  # existed at HEAD
    assert out["code"] == 1  # the new finding fails the gate
    assert any(f["location"].startswith("new.py") for f in out["findings"])


def test_no_new_findings_exits_zero(repo, capsys):
    (repo / "readme.txt").write_text("hello\n")
    out = run_json(repo, capsys, "--since", "HEAD", "--fail-on", "low")
    assert out["code"] == 0 and out["findings"] == []


def test_moved_code_is_not_new_but_a_second_identical_issue_is(repo, capsys):
    # shift the existing finding down several lines: same fingerprint, so not new
    (repo / "app.py").write_text("\n\n\nimport hashlib\nhashlib.md5(b'a')\n", encoding="utf-8")
    assert run_json(repo, capsys, "--since", "HEAD", "--fail-on", "low")["code"] == 0
    # a second identical use in the same file is a new occurrence
    (repo / "app.py").write_text(
        "import hashlib\nhashlib.md5(b'a')\nhashlib.md5(b'b')\n", encoding="utf-8"
    )
    out = run_json(repo, capsys, "--since", "HEAD", "--fail-on", "low")
    assert out["code"] == 1 and len(out["findings"]) == 1


def test_text_output_says_what_was_hidden(repo, capsys):
    main(["scan", str(repo), "--no-osv", "--no-color", "--since", "HEAD"])
    out = capsys.readouterr().out
    assert "Diff mode: showing findings new since HEAD; 1 unchanged finding(s) hidden." in out
    assert "weak hash" not in out


def test_subdirectory_scan_maps_to_the_same_subtree_at_the_ref(repo, capsys):
    sub = repo / "svc"
    sub.mkdir()
    (sub / "a.py").write_text("import hashlib\nhashlib.md5(b'a')\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "svc")
    (sub / "b.py").write_text("import hashlib\nhashlib.sha1(b'x')\n", encoding="utf-8")
    out = run_json(sub, capsys, "--since", "HEAD", "--fail-on", "low")
    assert [f["location"].split(":")[0] for f in out["findings"]] == ["b.py"]


def test_bad_refs_and_non_repositories_are_clean_errors(repo, tmp_path_factory, capsys):
    assert main(["scan", str(repo), "--no-osv", "--since", "no-such-ref"]) == 2
    assert "--since no-such-ref" in capsys.readouterr().err
    with pytest.raises(SystemExit):  # argparse refuses a value that looks like an option
        main(["scan", str(repo), "--no-osv", "--since", "--upload-pack=evil"])
    capsys.readouterr()
    assert main(["scan", str(repo), "--no-osv", "--since=--upload-pack=evil"]) == 2
    plain = tmp_path_factory.mktemp("plain")
    (plain / "a.py").write_text("x = 1\n")
    assert main(["scan", str(plain), "--no-osv", "--since", "HEAD"]) == 2


def test_export_rejects_option_like_refs(repo, tmp_path):
    with pytest.raises(GitDiffError):
        export_ref(str(repo), "--output=/tmp/x", str(tmp_path))


def test_split_new_consumes_the_multiset():
    from collections import Counter

    new, same = split_new([("a", 1), ("a", 2), ("b", 3)], Counter({"a": 1}))
    assert [x for _, x in same] == [1] and [x for _, x in new] == [2, 3]


def test_mcp_scan_diff(repo, monkeypatch):
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(repo))
    (repo / "new.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    r = handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "scan_diff", "arguments": {"path": str(repo), "since": "HEAD"}},
        }
    )
    payload = json.loads(r["result"]["content"][0]["text"])
    assert payload["since"] == "HEAD" and payload["unchanged_hidden"] == 1
    assert [f["location"].split(":")[0] for f in payload["findings"]] == ["new.py"]
