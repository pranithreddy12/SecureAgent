"""Tests for the static secret scanner. All planted values are fake."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analysis import secrets
from app.analysis.ingest import iter_source_files
from app.analysis.scanner import scan_repo
from app.cli import main

# Fake, non-functional values used only to exercise the detectors.
FAKE_AWS_ID = "AKIA" + "Q" * 16
FAKE_GH = "ghp_" + "a1B2c3D4" * 4 + "ab12"  # ghp_ + 36 chars
FAKE_HIGH_ENTROPY = "Zx9Qw3Vb7Np2Lk8Rt4Ya1Hs6Dc0Mf5"  # 31 chars, high entropy


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / ".git").mkdir()

    (tmp_path / "app" / "config.py").write_text(
        f'DEBUG = True\nAPI_SECRET = "{FAKE_HIGH_ENTROPY}"\nDB_HOST = "localhost"\n',
        encoding="utf-8",
    )
    (tmp_path / "app" / "aws.ini").write_text(
        f"aws_access_key_id = {FAKE_AWS_ID}\n", encoding="utf-8"
    )
    (tmp_path / "deploy.sh").write_text(f'export GH_TOKEN="{FAKE_GH}"\n', encoding="utf-8")
    # Clean file: references and placeholders must NOT be flagged.
    (tmp_path / "app" / "settings.py").write_text(
        'SECRET_KEY = os.environ["SECRET_KEY"]\n'
        'PASSWORD = "changeme"\n'
        'API_KEY = "your-api-key-here"\n'
        'note = "the password is stored in the vault"\n',
        encoding="utf-8",
    )
    # Vendored + VCS dirs must be skipped entirely.
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text(
        f'const k = "{FAKE_GH}";\n', encoding="utf-8"
    )
    (tmp_path / ".git" / "config").write_text(f"token={FAKE_AWS_ID}\n", encoding="utf-8")
    # Binary file must be skipped.
    (tmp_path / "app" / "logo.png").write_bytes(b"\x89PNG\r\n\x00\x00" + FAKE_AWS_ID.encode())
    return tmp_path


def test_entropy_and_redaction() -> None:
    assert secrets.shannon_entropy("aaaaaa") < 1.0
    assert secrets.shannon_entropy(FAKE_HIGH_ENTROPY) > 3.6
    red = secrets.redact(FAKE_HIGH_ENTROPY)
    assert FAKE_HIGH_ENTROPY not in red
    assert red.startswith("Zx") and f"len {len(FAKE_HIGH_ENTROPY)}" in red


def test_detects_planted_secrets(repo: Path) -> None:
    result = scan_repo(str(repo))
    rules = {f.rule for f in result.secret_findings}
    assert "AWS access key id" in rules
    assert "GitHub token" in rules
    assert any("API_SECRET" in r for r in rules)


def test_skips_vendored_vcs_and_binary(repo: Path) -> None:
    result = scan_repo(str(repo))
    hit_files = {f.relpath for f in result.secret_findings}
    assert not any(p.startswith("node_modules") for p in hit_files)
    assert not any(p.startswith(".git") for p in hit_files)
    assert not any(p.endswith(".png") for p in hit_files)


def test_placeholders_and_env_refs_not_flagged(repo: Path) -> None:
    result = scan_repo(str(repo))
    settings_hits = [f for f in result.secret_findings if f.relpath == "app/settings.py"]
    assert settings_hits == []


def test_full_secret_value_never_in_findings(repo: Path) -> None:
    result = scan_repo(str(repo))
    blob = json.dumps([f.__dict__ for f in result.secret_findings])
    for secret in (FAKE_AWS_ID, FAKE_GH, FAKE_HIGH_ENTROPY):
        assert secret not in blob  # only redacted previews + fingerprints are stored


def test_ingest_respects_max_files(repo: Path) -> None:
    files = list(iter_source_files(str(repo), max_files=1))
    assert len(files) == 1


def test_cli_text_and_exit_code(repo: Path, capsys: pytest.CaptureFixture) -> None:
    code = main(["scan", str(repo), "--no-color"])
    out = capsys.readouterr().out
    assert code == 1  # findings present -> non-zero (gates CI)
    assert "potential hardcoded secret" in out
    assert FAKE_AWS_ID not in out and FAKE_GH not in out  # redacted in console too


def test_cli_json_output(repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out_file = tmp_path / "out.json"
    code = main(["scan", str(repo), "--format", "json", "--output", str(out_file)])
    assert code == 1
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["stats"]["files_scanned"] >= 3
    assert len(data["secret_findings"]) >= 3
    assert all("fingerprint" in f and "redacted" in f for f in data["secret_findings"])


def test_cli_clean_repo_exit_zero(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    (tmp_path / "main.py").write_text("print('hello world')\n", encoding="utf-8")
    code = main(["scan", str(tmp_path), "--no-color"])
    assert code == 0
    assert "No hardcoded secrets detected" in capsys.readouterr().out


def test_cli_bad_path_exit_two(capsys: pytest.CaptureFixture) -> None:
    assert main(["scan", "/no/such/path/here"]) == 2
