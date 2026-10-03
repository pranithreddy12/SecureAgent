"""SecureAgent command-line scanner.

Static, read-only analysis of a source tree you own or are authorized to audit.
Usable standalone (no database or web server required):

    python -m app.cli scan /path/to/repo
    python -m app.cli scan /path/to/repo --format json --output findings.json

Exit code is 1 when findings are present (so it can gate CI), 0 when clean, 2 on error.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from app.analysis.ingest import IngestError
from app.analysis.scanner import ScanResult, scan_repo

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "informational": "\033[37m",
}
_RESET = "\033[0m"


def _render_text(result: ScanResult, color: bool) -> str:
    lines: list[str] = []
    secrets = result.ordered_secrets
    lines.append(f"SecureAgent static scan — {result.root}")
    lines.append(
        f"Scanned {result.stats.files_scanned} files "
        f"({result.stats.bytes_scanned // 1024} KiB); "
        f"skipped {result.stats.skipped_binary} binary, "
        f"{result.stats.skipped_too_large} oversized."
    )
    if result.stats.truncated:
        lines.append("WARNING: scan was truncated by a limit; results are partial.")
    lines.append("")

    if not secrets:
        lines.append("No hardcoded secrets detected.")
        return "\n".join(lines)

    counts = {k: v for k, v in result.severity_counts().items() if v}
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    lines.append(f"{len(secrets)} potential hardcoded secret(s): {summary}")
    lines.append("")
    for f in secrets:
        tag = f"[{f.severity.upper()}]"
        if color:
            tag = f"{_COLORS.get(f.severity, '')}{tag}{_RESET}"
        lines.append(f"{tag} {f.rule}")
        lines.append(f"    {f.relpath}:{f.line}")
        lines.append(f"    value: {f.redacted}   confidence: {f.confidence:.0%}")
        lines.append("")
    lines.append(
        "Rotate each exposed credential and remove it from source "
        "(use environment variables or a secrets manager)."
    )
    return "\n".join(lines)


def _render_json(result: ScanResult) -> str:
    payload = {
        "root": result.root,
        "stats": {
            "files_scanned": result.stats.files_scanned,
            "bytes_scanned": result.stats.bytes_scanned,
            "skipped_binary": result.stats.skipped_binary,
            "skipped_too_large": result.stats.skipped_too_large,
            "truncated": result.stats.truncated,
        },
        "secret_findings": [asdict(f) for f in result.ordered_secrets],
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secureagent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Static scan of a source tree.")
    scan.add_argument("path", help="Directory to scan (you must be authorized to analyse it).")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--output", help="Write the report to this file instead of stdout.")
    scan.add_argument(
        "--max-files", type=int, default=None, help="Cap the number of files scanned."
    )
    scan.add_argument("--no-color", action="store_true", help="Disable coloured text output.")
    args = parser.parse_args(argv)

    try:
        result = scan_repo(args.path, max_files=args.max_files)
    except (IngestError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color = (not args.no_color) and sys.stdout.isatty() and args.format == "text"
    report = _render_json(result) if args.format == "json" else _render_text(result, color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"Wrote {len(result.secret_findings)} finding(s) to {args.output}", file=sys.stderr)
    else:
        print(report)

    return 1 if result.secret_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
