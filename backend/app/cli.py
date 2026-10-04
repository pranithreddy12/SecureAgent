"""SecureAgent command-line scanner.

Static, read-only analysis of a source tree you own or are authorized to audit.
Usable standalone (no database or web server required):

    python -m app.cli scan /path/to/repo
    python -m app.cli scan /path/to/repo --format json --output findings.json
    python -m app.cli scan /path/to/repo --report report.html --pdf report.pdf

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


def _tag(severity: str, color: bool) -> str:
    t = f"[{severity.upper()}]"
    return f"{_COLORS.get(severity, '')}{t}{_RESET}" if color else t


def _render_text(result: ScanResult, color: bool) -> str:
    lines: list[str] = [f"SecureAgent static scan — {result.root}"]
    lines.append(
        f"Scanned {result.stats.files_scanned} files "
        f"({result.stats.bytes_scanned // 1024} KiB); "
        f"{len(result.routes)} route(s), {len(result.dependencies)} dependency(ies) found; "
        f"skipped {result.stats.skipped_binary} binary, "
        f"{result.stats.skipped_too_large} oversized."
    )
    if result.stats.truncated:
        lines.append("WARNING: scan was truncated by a limit; results are partial.")
    if result.osv_note:
        lines.append(result.osv_note)
    lines.append("")

    if result.total_findings == 0:
        lines.append(
            "No hardcoded secrets, vulnerable dependencies or unprotected endpoints detected."
        )
        return "\n".join(lines)

    counts = {k: v for k, v in result.severity_counts().items() if v}
    lines.append(
        f"{result.total_findings} finding(s): " + ", ".join(f"{v} {k}" for k, v in counts.items())
    )

    if result.ordered_secrets:
        lines.append("\nHardcoded secrets:")
        for f in result.ordered_secrets:
            lines.append(f"  {_tag(f.severity, color)} {f.rule}")
            lines.append(f"      {f.relpath}:{f.line}")
            lines.append(f"      value: {f.redacted}   confidence: {f.confidence:.0%}")

    if result.ordered_taint_findings:
        lines.append("\nInjection risks (untrusted input reaches a sink):")
        for f in result.ordered_taint_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.vuln_type.replace('_', ' ')} → {f.sink}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})")

    if result.ordered_sink_findings:
        lines.append("\nDangerous code patterns:")
        for f in result.ordered_sink_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.category.replace('_', ' ')} — {f.rule}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})")

    if result.ordered_dependency_findings:
        lines.append("\nVulnerable dependencies (known advisories in OSV):")
        for f in result.ordered_dependency_findings:
            d = f.dependency
            ids = ", ".join(v.id for v in f.vulns[:5])
            lines.append(f"  {_tag(f.severity, color)} {d.name} {d.version}  ({d.ecosystem})")
            lines.append(f"      {d.relpath}   {len(f.vulns)} advisory(ies): {ids}")

    if result.ordered_route_findings:
        lines.append(
            "\nEndpoints without visible authorization (review — may be globally guarded):"
        )
        for f in result.ordered_route_findings:
            r = f.route
            lines.append(f"  {_tag(f.severity, color)} {r.method} {r.path}")
            lines.append(f"      {r.relpath}:{r.line}   confidence: {f.confidence:.0%}")

    lines.append(
        "\nReview each finding above. Run with --report report.html for the full report "
        "with CWE/OWASP mapping and remediation for every finding."
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
        "routes_found": len(result.routes),
        "dependencies_found": len(result.dependencies),
        "osv_note": result.osv_note,
        "secret_findings": [asdict(f) for f in result.ordered_secrets],
        "injection_findings": [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "sink": f.sink,
                "relpath": f.relpath,
                "line": f.line,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "evidence": f.evidence,
            }
            for f in result.ordered_taint_findings
        ],
        "dangerous_sink_findings": [
            {
                "category": f.category,
                "rule": f.rule,
                "severity": f.severity,
                "confidence": f.confidence,
                "relpath": f.relpath,
                "line": f.line,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "evidence": f.evidence,
            }
            for f in result.ordered_sink_findings
        ],
        "dependency_findings": [
            {
                "severity": f.severity,
                "confidence": f.confidence,
                "ecosystem": f.dependency.ecosystem,
                "name": f.dependency.name,
                "version": f.dependency.version,
                "relpath": f.dependency.relpath,
                "advisories": [
                    {"id": v.id, "severity": v.severity, "summary": v.summary, "url": v.url}
                    for v in f.vulns
                ],
            }
            for f in result.ordered_dependency_findings
        ],
        "authorization_findings": [
            {
                "severity": f.severity,
                "confidence": f.confidence,
                "method": f.route.method,
                "path": f.route.path,
                "framework": f.route.framework,
                "relpath": f.route.relpath,
                "line": f.route.line,
                "reason": f.reason,
            }
            for f in result.ordered_route_findings
        ],
    }
    return json.dumps(payload, indent=2)


def _write_report(result: ScanResult, html_path: str | None, pdf_path: str | None) -> None:
    from app.analysis.reporting import scan_to_report_context
    from app.reports.renderer import render_html

    ctx = scan_to_report_context(result)
    html = render_html(ctx)
    if html_path:
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"Wrote HTML report to {html_path}", file=sys.stderr)
    if pdf_path:
        from app.reports.renderer import render_pdf

        with open(pdf_path, "wb") as fh:
            fh.write(render_pdf(html))
        print(f"Wrote PDF report to {pdf_path}", file=sys.stderr)


def _force_utf8_output() -> None:
    # Reports use typographic characters; a legacy console (Windows cp1252) would
    # otherwise raise UnicodeEncodeError. Degrade gracefully if reconfigure is absent.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = argparse.ArgumentParser(prog="secureagent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Static scan of a source tree.")
    scan.add_argument("path", help="Directory to scan (you must be authorized to analyse it).")
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--output", help="Write the text/JSON result to this file instead of stdout.")
    scan.add_argument("--report", help="Write a professional HTML report to this path.")
    scan.add_argument("--pdf", help="Write a PDF report to this path (needs WeasyPrint libs).")
    scan.add_argument(
        "--max-files", type=int, default=None, help="Cap the number of files scanned."
    )
    scan.add_argument(
        "--no-osv", action="store_true", help="Skip the OSV known-vulnerability lookup (offline)."
    )
    scan.add_argument("--no-color", action="store_true", help="Disable coloured text output.")
    args = parser.parse_args(argv)

    try:
        result = scan_repo(args.path, max_files=args.max_files, check_osv=not args.no_osv)
    except (IngestError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    color = (not args.no_color) and sys.stdout.isatty() and args.format == "text"
    report = _render_json(result) if args.format == "json" else _render_text(result, color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"Wrote result to {args.output}", file=sys.stderr)
    else:
        print(report)

    if args.report or args.pdf:
        try:
            _write_report(result, args.report, args.pdf)
        except (OSError, ImportError) as exc:
            print(f"error: could not render report: {exc}", file=sys.stderr)
            return 2

    return 1 if result.total_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
