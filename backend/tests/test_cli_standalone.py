"""The installed `secureagent` command must work on a machine that has only the CLI's declared
dependencies (no SQLAlchemy / FastAPI / asyncpg / database). A clean `pip install` once crashed
here because the scanner path imported the ORM package; this guards against that regression."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]

# Make the web-stack imports fail exactly as they would on a clean install.
POISON = (
    "import sys\n"
    "for m in ('sqlalchemy','asyncpg','fastapi','alembic','psycopg2','argon2','jwt','uvicorn'):\n"
    "    sys.modules[m] = None\n"
    "from app.cli import main\n"
    "raise SystemExit(main({argv!r}))\n"
)


def run_cli(argv: list[str]) -> subprocess.CompletedProcess:
    code = POISON.format(argv=argv)
    return subprocess.run(  # noqa: S603 - fixed interpreter, test-controlled arguments
        [sys.executable, "-c", code],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={"PYTHONIOENCODING": "utf-8", "PATH": "", "SYSTEMROOT": r"C:\Windows"},
        timeout=120,
    )


@pytest.fixture
def vulnerable_dir(tmp_path: Path) -> Path:
    (tmp_path / "s.py").write_text("DEBUG = True\n", encoding="utf-8")
    return tmp_path


def test_scan_works_without_the_web_stack(vulnerable_dir: Path) -> None:
    res = run_cli(["scan", str(vulnerable_dir), "--no-osv", "--no-color"])
    assert "ModuleNotFoundError" not in res.stderr and "ImportError" not in res.stderr, res.stderr
    assert res.returncode == 1  # a medium misconfiguration is present
    assert "DEBUG = True" in res.stdout


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_machine_formats_work_without_the_web_stack(vulnerable_dir: Path, fmt: str) -> None:
    res = run_cli(["scan", str(vulnerable_dir), "--no-osv", "--format", fmt])
    assert "Error" not in res.stderr, res.stderr
    assert res.stdout.lstrip().startswith("{")


def test_report_and_demo_work_without_the_web_stack(tmp_path: Path) -> None:
    out = tmp_path / "demo.html"
    res = run_cli(["demo", "--no-color", "--report", str(out)])
    assert "Error" not in res.stderr, res.stderr
    assert res.returncode == 0 and "DEMO / SIMULATED SECURITY AUDIT" in out.read_text("utf-8")
