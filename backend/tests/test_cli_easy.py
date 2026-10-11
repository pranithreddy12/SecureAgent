"""One-command usage: `secureagent`, `secureagent PATH`, and `scan --open`."""

from __future__ import annotations

import webbrowser
from pathlib import Path

import pytest

from app.cli import _expand_shorthand, main

VULN = "import hashlib\nhashlib.md5(b'x')\n"


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(webbrowser, "open", lambda uri: calls.append(uri) or True)
    return calls


def test_shorthand_expansion():
    assert _expand_shorthand([]) == ["scan", ".", "--open", "--exit-zero"]
    assert _expand_shorthand(["./app"]) == ["scan", "./app", "--open", "--exit-zero"]
    assert _expand_shorthand(["scan", "x", "--no-osv"]) == ["scan", "x", "--no-osv"]
    assert _expand_shorthand(["demo"]) == ["demo"]
    assert _expand_shorthand(["--help"]) == ["--help"]


def test_scan_defaults_to_the_current_directory(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--no-osv", "--no-color"]) == 1  # findings, and no --exit-zero
    assert "weak hash" in capsys.readouterr().out


def test_open_writes_the_report_to_a_temp_file_and_opens_it(tmp_path, opened, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    code = main(["scan", str(tmp_path), "--no-osv", "--no-color", "--open", "--exit-zero"])
    assert code == 0
    assert len(opened) == 1 and opened[0].startswith("file:")
    report = Path(opened[0].removeprefix("file:///").replace("%20", " "))
    html = report.read_text(encoding="utf-8")
    assert "SecureAgent" in html and "weak" in html.lower()
    # the project directory itself is not polluted with report files
    assert [p.name for p in tmp_path.iterdir()] == ["app.py"]


def test_bare_path_argument_scans_and_opens(tmp_path, opened):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    code = main([str(tmp_path), "--no-osv"])  # shorthand + a scan flag
    assert code == 0 and len(opened) == 1


def test_explicit_report_path_is_reused_when_opening(tmp_path, opened):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    out = tmp_path.parent / f"{tmp_path.name}-report.html"
    main(["scan", str(tmp_path), "--no-osv", "--report", str(out), "--open", "--exit-zero"])
    assert out.is_file() and len(opened) == 1
    assert Path(out).name in opened[0]


def test_open_prints_the_uri_when_no_browser_is_available(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    monkeypatch.setattr(webbrowser, "open", lambda uri: False)
    main(["scan", str(tmp_path), "--no-osv", "--open", "--exit-zero"])
    assert "Open the report in your browser: file:" in capsys.readouterr().err
