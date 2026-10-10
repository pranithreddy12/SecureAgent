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
import contextlib
import json
import sys
from dataclasses import asdict

from app.analysis.ingest import IngestError
from app.analysis.intent import IntentError
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
    if result.stats.excluded:
        lines.append(f"{result.stats.excluded} file(s) excluded by --exclude / .secureagentignore.")
    if result.inline_ignored:
        lines.append(
            f"{result.inline_ignored} finding(s) hidden by inline `secureagent: ignore` comments."
        )
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

    if result.ordered_misconfig_findings:
        lines.append("\nSecurity misconfigurations:")
        for f in result.ordered_misconfig_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.rule}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})")

    if result.ordered_logging_findings:
        lines.append("\nLogging & monitoring:")
        for f in result.ordered_logging_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.rule}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})")

    if result.ordered_logic_findings:
        lines.append("\nBusiness-logic flaws (client-trusted values, declared-rule violations):")
        for f in result.ordered_logic_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.title}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})  confidence: {f.confidence:.0%}")

    if result.ordered_idor_findings:
        lines.append("\nBroken object-level authorization (possible IDOR):")
        for f in result.ordered_idor_findings:
            lines.append(f"  {_tag(f.severity, color)} {f.handler}() — lookup via {f.lookup}")
            lines.append(f"      {f.relpath}:{f.line}  ({f.cwe})  confidence: {f.confidence:.0%}")

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


def _render_json(result: ScanResult, items=None, baseline=None) -> str:
    payload = {
        "root": result.root,
        "stats": {
            "files_scanned": result.stats.files_scanned,
            "bytes_scanned": result.stats.bytes_scanned,
            "skipped_binary": result.stats.skipped_binary,
            "skipped_too_large": result.stats.skipped_too_large,
            "truncated": result.stats.truncated,
            "excluded_files": result.stats.excluded,
            "inline_ignored_findings": result.inline_ignored,
        },
        "routes_found": len(result.routes),
        "dependencies_found": len(result.dependencies),
        "osv_note": result.osv_note,
        "secret_findings": [asdict(f) for f in result.ordered_secrets],
        "misconfig_findings": [
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
            for f in result.ordered_misconfig_findings
        ],
        "logging_findings": [
            {
                "category": f.category,
                "rule": f.rule,
                "severity": f.severity,
                "confidence": f.confidence,
                "relpath": f.relpath,
                "line": f.line,
                "cwe": f.cwe,
                "owasp": f.owasp,
            }
            for f in result.ordered_logging_findings
        ],
        "logic_findings": [
            {
                "category": f.category,
                "rule": f.rule,
                "severity": f.severity,
                "confidence": f.confidence,
                "handler": f.handler,
                "field": f.field,
                "relpath": f.relpath,
                "line": f.line,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "evidence": f.evidence,
            }
            for f in result.ordered_logic_findings
        ],
        "intent_rules_evaluated": result.intent_rules,
        "idor_findings": [
            {
                "severity": f.severity,
                "confidence": f.confidence,
                "handler": f.handler,
                "lookup": f.lookup,
                "relpath": f.relpath,
                "line": f.line,
                "cwe": f.cwe,
                "owasp": f.owasp,
            }
            for f in result.ordered_idor_findings
        ],
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
    if items is not None:
        base = baseline or set()
        payload["findings"] = [
            {
                "fingerprint": fp,
                "type": f.type,
                "severity": f.severity.value,
                "status": f.status.value,
                "cwe": f.cwe,
                "cve": f.cve,
                "owasp": f.owasp_category,
                "location": f.endpoint,
                "title": f.title,
                "baselined": fp in base,
            }
            for fp, f in items
        ]
        payload["summary"] = {
            "total": len(items),
            "new": sum(1 for fp, _ in items if fp not in base),
            "baselined": sum(1 for fp, _ in items if fp in base),
        }
    return json.dumps(payload, indent=2)


DEMO_BANNER = (
    "=" * 72 + "\n"
    "DEMO MODE -- scanning SecureAgent's bundled, deliberately vulnerable sample app.\n"
    "This is NOT a real system. The flaws below were planted on purpose; the analysis\n"
    "itself is the real SecureAgent engine. (safe_routes.py is correct code and should\n"
    "produce no findings.)\n" + "=" * 72
)


def _run_demo(args) -> int:
    from app.demo import sample_app_path

    root = sample_app_path()
    if not root.is_dir():
        print(f"error: demo sample not found at {root}", file=sys.stderr)
        return 2
    result = scan_repo(str(root), check_osv=args.online)
    if not args.online and result.dependencies:
        result.osv_note = (
            "Known-vulnerability lookup skipped in offline demo (use --online to query OSV)."
        )
    color = (not args.no_color) and sys.stdout.isatty()
    print(DEMO_BANNER)
    print(_render_text(result, color))
    if args.report or args.pdf:
        try:
            _write_report(result, args.report, args.pdf, demo=True)
        except (OSError, ImportError) as exc:
            print(f"error: could not render report: {exc}", file=sys.stderr)
            return 2
    return 0  # a showcase, not a gate


def _write_report(
    result: ScanResult, html_path: str | None, pdf_path: str | None, demo: bool = False
) -> None:
    from app.analysis.reporting import scan_to_report_context
    from app.reports.renderer import render_html

    ctx = scan_to_report_context(
        result, repo_label="Vulnerable Shop (DEMO)" if demo else None, demo=demo
    )
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
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]


def main(argv: list[str] | None = None) -> int:
    _force_utf8_output()
    parser = argparse.ArgumentParser(prog="secureagent", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Static scan of a source tree.")
    scan.add_argument("path", help="Directory to scan (you must be authorized to analyse it).")
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", help="Write the text/JSON result to this file instead of stdout.")
    scan.add_argument("--report", help="Write a professional HTML report to this path.")
    scan.add_argument("--pdf", help="Write a PDF report to this path (needs WeasyPrint libs).")
    scan.add_argument(
        "--max-files", type=int, default=None, help="Cap the number of files scanned."
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Skip files matching a glob (e.g. 'tests/*', '*.min.js', 'fixtures/'). Repeatable. "
        "Patterns in <path>/.secureagentignore are applied too.",
    )
    scan.add_argument(
        "--no-osv", action="store_true", help="Skip the OSV known-vulnerability lookup (offline)."
    )
    scan.add_argument(
        "--intent",
        metavar="FILE",
        help="Developer intent spec (JSON rules the code must satisfy). "
        "Defaults to <path>/secureagent-intent.json when present.",
    )
    scan.add_argument("--baseline", help="Suppress findings listed in this baseline file.")
    scan.add_argument(
        "--write-baseline", help="Write all current findings to this baseline file and exit."
    )
    scan.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit non-zero only if a new finding at or above this severity remains.",
    )
    scan.add_argument("--no-color", action="store_true", help="Disable coloured text output.")

    demo = sub.add_parser(
        "demo", help="Scan the bundled deliberately-vulnerable sample app (works offline)."
    )
    demo.add_argument("--report", help="Write the demo HTML report (labelled DEMO) to this path.")
    demo.add_argument("--pdf", help="Write the demo PDF report to this path.")
    demo.add_argument(
        "--online", action="store_true", help="Also query OSV for the sample's pinned dependencies."
    )
    demo.add_argument("--no-color", action="store_true", help="Disable coloured text output.")
    args = parser.parse_args(argv)
    if args.command == "demo":
        return _run_demo(args)

    try:
        result = scan_repo(
            args.path,
            max_files=args.max_files,
            check_osv=not args.no_osv,
            exclude=args.exclude,
            intent=args.intent,
        )
    except (IngestError, IntentError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Unified findings drive baselining, the JSON canonical list, and CI gating.
    from app.analysis.baseline import fails_threshold, fingerprint, load_baseline, write_baseline
    from app.analysis.reporting import scan_to_report_context

    unified = scan_to_report_context(result).findings
    items = [(fingerprint(f), f) for f in unified]

    if args.write_baseline:
        n = write_baseline(args.write_baseline, [fp for fp, _ in items])
        print(f"Wrote baseline with {n} fingerprint(s) to {args.write_baseline}", file=sys.stderr)
        return 0

    baseline = load_baseline(args.baseline) if args.baseline else set()
    new_items = [(fp, f) for fp, f in items if fp not in baseline]
    suppressed = len(items) - len(new_items)

    color = (not args.no_color) and sys.stdout.isatty() and args.format == "text"
    if args.format == "sarif":
        from app.analysis.sarif import to_sarif

        report = json.dumps(to_sarif([f for _, f in items]), indent=2)
    elif args.format == "json":
        report = _render_json(result, items, baseline)
    else:
        report = _render_text(result, color)
        if args.baseline:
            report += f"\nBaseline: {suppressed} suppressed, {len(new_items)} new."

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

    gating = new_items if args.baseline else items
    if args.fail_on:
        failed = any(fails_threshold(f.severity.value, args.fail_on) for _, f in gating)
    else:
        failed = bool(gating)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
