"""Run the static analysers over an ingested source tree and collect findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis import secrets
from app.analysis.ingest import IngestStats, SourceFile, iter_source_files, read_text
from app.analysis.secrets import SecretFinding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


@dataclass
class ScanResult:
    root: str
    secret_findings: list[SecretFinding] = field(default_factory=list)
    stats: IngestStats = field(default_factory=IngestStats)

    @property
    def ordered_secrets(self) -> list[SecretFinding]:
        return sorted(
            self.secret_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.confidence, f.relpath, f.line),
        )

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for f in self.secret_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def scan_repo(root: str, *, max_files: int | None = None) -> ScanResult:
    """Ingest ``root`` (read-only) and run all static analysers."""
    stats = IngestStats()
    result = ScanResult(root=str(root), stats=stats)
    kwargs = {"stats": stats}
    if max_files is not None:
        kwargs["max_files"] = max_files

    file: SourceFile
    for file in iter_source_files(root, **kwargs):
        try:
            text = read_text(file)
        except OSError:
            continue
        result.secret_findings.extend(secrets.scan_text(file.relpath, text))

    return result
