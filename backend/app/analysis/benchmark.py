"""Measure detector accuracy against a labelled corpus.

A corpus is a directory of source files in which every line that should produce a finding
carries a ``VULN:<finding_type>`` marker comment. The scanner is run over it and each finding
is matched to a marker by (file, line, type):

- marker with a matching finding -> true positive
- marker with no matching finding -> false negative (a miss)
- finding with no marker         -> false positive

The numbers are only as good as the corpus: the bundled one is authored by the project and is
small, so it measures regressions and known weaknesses, not performance on the real world.
Point ``secureagent benchmark`` at a larger labelled corpus to measure that.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from app.analysis.ingest import iter_source_files, read_text
from app.analysis.reporting import scan_to_report_context
from app.analysis.scanner import scan_repo

MARKER = re.compile(r"VULN:\s*([a-z][a-z0-9_]*)")
_LINE_SUFFIX = re.compile(r":(\d+)$")


@dataclass
class TypeStats:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None


@dataclass
class BenchmarkResult:
    by_type: dict[str, TypeStats] = field(default_factory=lambda: defaultdict(TypeStats))
    false_positives: list[tuple[str, int, str]] = field(default_factory=list)
    misses: list[tuple[str, int, str]] = field(default_factory=list)
    files: int = 0

    @property
    def total(self) -> TypeStats:
        t = TypeStats()
        for s in self.by_type.values():
            t.tp += s.tp
            t.fp += s.fp
            t.fn += s.fn
        return t


def expected_markers(root: str) -> set[tuple[str, int, str]]:
    out: set[tuple[str, int, str]] = set()
    for f in iter_source_files(root):
        try:
            text = read_text(f)
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for m in MARKER.finditer(line):
                out.add((f.relpath, lineno, m.group(1)))
    return out


def run_benchmark(root: str) -> BenchmarkResult:
    expected = expected_markers(root)
    result = scan_repo(root, check_osv=False)
    findings = scan_to_report_context(result).findings
    found: set[tuple[str, int, str]] = set()
    for f in findings:
        m = _LINE_SUFFIX.search(f.endpoint or "")
        if not m:
            continue  # not a file:line location (nothing to match against)
        found.add((f.endpoint[: m.start()], int(m.group(1)), f.type))

    out = BenchmarkResult(files=result.stats.files_scanned)
    for key in sorted(expected & found):
        out.by_type[key[2]].tp += 1
    for key in sorted(expected - found):
        out.by_type[key[2]].fn += 1
        out.misses.append(key)
    for key in sorted(found - expected):
        out.by_type[key[2]].fp += 1
        out.false_positives.append(key)
    return out


def format_result(r: BenchmarkResult) -> str:
    def pct(v: float | None) -> str:
        return "  n/a" if v is None else f"{v:5.0%}"

    lines = [
        f"Benchmark over {r.files} file(s)",
        "",
        f"{'finding type':<40} {'TP':>3} {'FP':>3} {'FN':>3} {'precision':>10} {'recall':>8}",
    ]
    for t, s in sorted(r.by_type.items()):
        lines.append(
            f"{t:<40} {s.tp:>3} {s.fp:>3} {s.fn:>3} {pct(s.precision):>10} {pct(s.recall):>8}"
        )
    tot = r.total
    lines += [
        "-" * 70,
        f"{'TOTAL':<40} {tot.tp:>3} {tot.fp:>3} {tot.fn:>3} "
        f"{pct(tot.precision):>10} {pct(tot.recall):>8}",
    ]
    if r.misses:
        lines += ["", "Missed (false negatives):"]
        lines += [f"  {p}:{ln}  {t}" for p, ln, t in r.misses]
    if r.false_positives:
        lines += ["", "Unexpected findings (false positives):"]
        lines += [f"  {p}:{ln}  {t}" for p, ln, t in r.false_positives]
    return "\n".join(lines)
