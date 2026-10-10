"""Detector accuracy benchmark: harness behaviour and a regression floor on the bundled corpus."""

from __future__ import annotations

import textwrap
from pathlib import Path

from app.analysis.benchmark import expected_markers, run_benchmark
from app.cli import main

CORPUS = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"


def test_marker_parsing(tmp_path):
    (tmp_path / "a.py").write_text("x = 1  # VULN:sql_injection\ny = 2\n", encoding="utf-8")
    assert expected_markers(str(tmp_path)) == {("a.py", 1, "sql_injection")}


def test_harness_counts_tp_fp_fn(tmp_path):
    src = textwrap.dedent(
        """
        import hashlib
        a = hashlib.md5(b"x")  # VULN:weak_hash
        b = hashlib.sha1(b"x")
        c = 1  # VULN:swallowed_exception
        """
    )
    (tmp_path / "m.py").write_text(src, encoding="utf-8")
    r = run_benchmark(str(tmp_path))
    assert r.by_type["weak_hash"].tp == 1  # marked line found
    assert r.by_type["weak_hash"].fp == 1  # unmarked md5/sha1 finding counts against precision
    assert r.by_type["swallowed_exception"].fn == 1  # marker with no finding is a miss
    assert r.total.precision == 0.5


def test_bundled_corpus_does_not_regress():
    r = run_benchmark(str(CORPUS))
    total = r.total
    assert r.files >= 4
    assert total.tp + total.fn >= 30  # corpus did not silently shrink
    assert (total.precision or 0) >= 0.9, r.false_positives
    assert (total.recall or 0) >= 0.9, r.misses


def test_cli_benchmark_threshold_exit_codes(capsys):
    assert main(["benchmark", str(CORPUS), "--min-precision", "0.5", "--min-recall", "0.5"]) == 0
    assert "TOTAL" in capsys.readouterr().out
    assert main(["benchmark", str(CORPUS), "--min-recall", "1.01"]) == 1
    assert main(["benchmark", str(CORPUS / "missing")]) == 2
