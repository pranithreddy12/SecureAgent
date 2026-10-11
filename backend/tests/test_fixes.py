"""Verified fix patches (ADR-013)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from app.analysis import fixes
from app.analysis.fixes import apply_patches, propose_fixes
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo
from app.cli import main


def _setup(tmp_path: Path, name: str, src: str) -> Path:
    (tmp_path / name).write_text(textwrap.dedent(src), encoding="utf-8")
    return tmp_path


def _patches(root: Path):
    ctx = scan_to_report_context(scan_repo(str(root), check_osv=False))
    return propose_fixes(str(root), ctx.findings), ctx


def _types(root: Path) -> set[str]:
    return {f.type for f in scan_to_report_context(scan_repo(str(root), check_osv=False)).findings}


def test_single_line_fixers():
    cases = {
        "weak_hash": ("h = hashlib.md5(b'x')", "hashlib.sha256("),
        "disabled_tls_verification": ("r = requests.get(u, verify=False)", "verify=True"),
        "insecure_deserialization": ("d = yaml.load(s, Loader=yaml.Loader)", "yaml.safe_load(s)"),
        "debug_enabled": ('app.config["DEBUG"] = True', '"DEBUG"] = False'),
        "csrf_disabled": ('app.config["WTF_CSRF_ENABLED"] = False', 'ENABLED"] = True'),
        "jwt_verification_disabled": (
            "o = {'verify_signature': False}",
            "'verify_signature': True",
        ),
    }
    for ftype, (line, expect) in cases.items():
        new, *_ = fixes.FIXERS[ftype](line)
        assert expect in new, (ftype, new)


def test_unmatched_lines_have_no_fix():
    assert fixes.FIXERS["weak_hash"]("x = something_else()") is None
    assert fixes.FIXERS["insecure_deserialization"]("pickle.loads(data)") is None
    assert fixes.FIXERS["hardcoded_secret"]('headers = {"token": "x"}') is None


def test_patch_is_verified_and_removes_the_finding(tmp_path):
    root = _setup(
        tmp_path,
        "app.py",
        """
        import hashlib
        import requests

        def a(p):
            return hashlib.md5(p).hexdigest()

        def b(u):
            return requests.get(u, verify=False)
        """,
    )
    patches, _ = _patches(root)
    (patch,) = patches
    assert patch.verified, patch.note
    assert {c.finding_type for c in patch.changes} == {"weak_hash", "disabled_tls_verification"}
    assert "sha256" in patch.diff and "verify=True" in patch.diff
    assert all(c.caveat for c in patch.changes)  # every change says what to check

    assert apply_patches(str(root), patches) == ["app.py"]
    after = _types(root)
    assert "weak_hash" not in after and "disabled_tls_verification" not in after


def test_hardcoded_secret_becomes_env_lookup_with_import(tmp_path):
    root = _setup(
        tmp_path,
        "config.py",
        '''
        """Settings."""
        import json

        DB_PASSWORD = "Tr0ub4dor&3xK9vQ2mZ"
        ''',
    )
    patches, _ = _patches(root)
    (patch,) = patches
    assert patch.verified, patch.note
    assert 'DB_PASSWORD = os.environ["DB_PASSWORD"]' in patch.patched
    lines = patch.patched.strip().splitlines()
    assert lines[0] == '"""Settings."""'  # docstring stays first
    assert "import os" in lines[: lines.index('DB_PASSWORD = os.environ["DB_PASSWORD"]')]
    assert "Tr0ub4dor" not in patch.patched
    assert "rotate" in patch.changes[0].caveat


def test_import_os_is_not_duplicated(tmp_path):
    root = _setup(
        tmp_path,
        "config.py",
        """
        import os
        DB_PASSWORD = "Tr0ub4dor&3xK9vQ2mZ"
        """,
    )
    (patch,) = _patches(root)[0]
    assert patch.patched.count("import os") == 1


def test_apply_refuses_when_the_file_changed_after_the_scan(tmp_path):
    root = _setup(tmp_path, "app.py", "import hashlib\nhashlib.md5(b'x')\n")
    patches, _ = _patches(root)
    (root / "app.py").write_text("# edited meanwhile\nimport hashlib\nhashlib.md5(b'x')\n")
    assert apply_patches(str(root), patches) == []
    assert "md5" in (root / "app.py").read_text()


def test_unverified_patches_are_never_written(tmp_path, monkeypatch):
    root = _setup(tmp_path, "app.py", "import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setitem(
        fixes.FIXERS, "weak_hash", lambda line: (line + "  # noop", "x", "y", False)
    )
    patches, _ = _patches(root)
    (patch,) = patches
    assert not patch.verified and "did not remove" in patch.note
    assert apply_patches(str(root), patches) == []
    assert "md5" in (root / "app.py").read_text()


def test_syntax_breaking_fix_is_rejected(tmp_path, monkeypatch):
    root = _setup(tmp_path, "app.py", "import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setitem(
        fixes.FIXERS, "weak_hash", lambda line: ("hashlib.sha256((", "x", "y", False)
    )
    (patch,) = _patches(root)[0]
    assert not patch.verified and "does not parse" in patch.note


def test_crlf_files_keep_their_line_endings(tmp_path):
    (tmp_path / "app.py").write_bytes(b"import hashlib\r\nhashlib.md5(b'x')\r\n")
    patches, _ = _patches(tmp_path)
    assert apply_patches(str(tmp_path), patches) == ["app.py"]
    data = (tmp_path / "app.py").read_bytes()
    assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")
    assert b"sha256" in data


def test_symlinks_are_skipped(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    outside = tmp_path / "outside.py"
    outside.write_text("import hashlib\nhashlib.md5(b'x')\n")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link.py").symlink_to(outside)
    except OSError:
        return  # symlinks unavailable (e.g. Windows without privilege)
    patches, _ = _patches(root)
    assert patches == []
    assert "md5" in outside.read_text()


def test_cli_fix_dry_run_then_apply(tmp_path, capsys):
    root = _setup(tmp_path, "app.py", "import hashlib\nhashlib.md5(b'x')\n")
    assert main(["fix", str(root)]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "Dry run" in out
    assert "md5" in (root / "app.py").read_text()  # untouched

    assert main(["fix", str(root), "--apply"]) == 0
    assert "Applied to 1 file" in capsys.readouterr().out
    assert "sha256" in (root / "app.py").read_text()
    assert main(["fix", str(root)]) == 0
    assert "No automatic fixes" in capsys.readouterr().out


def test_mcp_suggest_fixes_never_writes(tmp_path, monkeypatch):
    from app.mcp_server import handle

    root = _setup(tmp_path, "app.py", "import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.setenv("SECUREAGENT_MCP_ROOTS", str(root))
    import json

    r = handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "suggest_fixes", "arguments": {"path": str(root)}},
        }
    )
    out = json.loads(r["result"]["content"][0]["text"])
    assert out["patches"][0]["verified"] is True
    assert "sha256" in out["patches"][0]["diff"]
    assert "md5" in (root / "app.py").read_text()


def test_secret_with_trailing_comment_keeps_the_comment(tmp_path):
    root = _setup(
        tmp_path,
        "config.py",
        """
        DB_PASSWORD = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"  # fake credential
        """,
    )
    (patch,) = _patches(root)[0]
    assert patch.verified, patch.note
    assert 'DB_PASSWORD = os.environ["DB_PASSWORD"]  # fake credential' in patch.patched
