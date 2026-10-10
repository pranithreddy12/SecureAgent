"""Run the static analysers over an ingested source tree and collect findings."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from app.analysis import secrets
from app.analysis.access_control import IdorFinding, analyze_access_control
from app.analysis.authz_matrix import authz_outliers
from app.analysis.business_logic import LogicFinding, analyze_business_logic
from app.analysis.dependencies import Dependency, is_lockfile, parse_dependencies
from app.analysis.ingest import (
    IngestStats,
    SourceFile,
    iter_source_files,
    load_ignore_file,
    read_text,
)
from app.analysis.intent import (
    DEFAULT_FILENAME,
    evaluate_intent,
    extra_fields,
    load_intent,
)
from app.analysis.logging_checks import LoggingFinding, scan_logging
from app.analysis.misconfig import MisconfigFinding, scan_misconfig
from app.analysis.osv import OsvClient, OsvError, Vuln
from app.analysis.routes import Route, RouteFinding, extract_routes, route_findings
from app.analysis.secrets import SecretFinding
from app.analysis.sinks import SinkFinding, scan_sinks
from app.analysis.taint import JS_EXTENSIONS, TaintFinding, analyze_taint_project

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "informational": 5}

# `# secureagent: ignore`, `// secureagent:ignore`, ... on the line a finding is reported at.
INLINE_IGNORE = re.compile(r"secureagent:\s*ignore", re.IGNORECASE)


@dataclass(frozen=True)
class DependencyFinding:
    dependency: Dependency
    vulns: list[Vuln]
    severity: str
    confidence: float

    @property
    def title(self) -> str:
        d = self.dependency
        return f"Vulnerable dependency: {d.name} {d.version}"


def _worst_severity(vulns: list[Vuln]) -> str:
    known = [v.severity for v in vulns if v.severity != "unknown"]
    if not known:
        return "medium"  # a known advisory with no rated severity is still worth fixing
    return min(known, key=lambda s: SEVERITY_ORDER.get(s, 9))


@dataclass
class ScanResult:
    root: str
    secret_findings: list[SecretFinding] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    route_findings: list[RouteFinding] = field(default_factory=list)
    sink_findings: list[SinkFinding] = field(default_factory=list)
    taint_findings: list[TaintFinding] = field(default_factory=list)
    idor_findings: list[IdorFinding] = field(default_factory=list)
    misconfig_findings: list[MisconfigFinding] = field(default_factory=list)
    logging_findings: list[LoggingFinding] = field(default_factory=list)
    logic_findings: list[LogicFinding] = field(default_factory=list)
    intent_rules: int = 0  # developer intent rules evaluated (0 = no spec supplied)
    dependencies: list[Dependency] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    osv_note: str | None = None
    inline_ignored: int = 0  # findings hidden by `secureagent: ignore` comments (always reported)
    stats: IngestStats = field(default_factory=IngestStats)

    @property
    def total_findings(self) -> int:
        return (
            len(self.secret_findings)
            + len(self.route_findings)
            + len(self.sink_findings)
            + len(self.taint_findings)
            + len(self.idor_findings)
            + len(self.misconfig_findings)
            + len(self.logging_findings)
            + len(self.logic_findings)
            + len(self.dependency_findings)
        )

    @property
    def ordered_secrets(self) -> list[SecretFinding]:
        return sorted(
            self.secret_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.confidence, f.relpath, f.line),
        )

    @property
    def ordered_route_findings(self) -> list[RouteFinding]:
        return sorted(
            self.route_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.route.relpath, f.route.line),
        )

    @property
    def ordered_sink_findings(self) -> list[SinkFinding]:
        return sorted(
            self.sink_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_taint_findings(self) -> list[TaintFinding]:
        return sorted(
            self.taint_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_idor_findings(self) -> list[IdorFinding]:
        return sorted(
            self.idor_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_misconfig_findings(self) -> list[MisconfigFinding]:
        return sorted(
            self.misconfig_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_logging_findings(self) -> list[LoggingFinding]:
        return sorted(
            self.logging_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_logic_findings(self) -> list[LogicFinding]:
        return sorted(
            self.logic_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.relpath, f.line),
        )

    @property
    def ordered_dependency_findings(self) -> list[DependencyFinding]:
        return sorted(
            self.dependency_findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.dependency.name),
        )

    def severity_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for f in self.secret_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.route_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.sink_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.taint_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.idor_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.misconfig_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.logging_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.logic_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.dependency_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def scan_repo(
    root: str,
    *,
    max_files: int | None = None,
    check_osv: bool = True,
    osv_client: OsvClient | None = None,
    exclude: Sequence[str] = (),
    intent: str | None = None,
) -> ScanResult:
    """Ingest ``root`` (read-only) and run all static analysers.

    ``exclude`` patterns (plus any in ``<root>/.secureagentignore``) skip files entirely;
    a ``secureagent: ignore`` comment hides findings reported on that line. Both are counted
    in the result so suppression is never silent.

    ``intent`` is a developer intent spec (ADR-010); ``<root>/secureagent-intent.json`` is used
    when present. A malformed spec raises ``IntentError`` rather than being ignored.
    """
    stats = IngestStats()
    result = ScanResult(root=str(root), stats=stats)
    kwargs: dict = {"stats": stats, "exclude": [*load_ignore_file(root), *exclude]}
    if max_files is not None:
        kwargs["max_files"] = max_files

    intent_path = intent or os.path.join(str(root), DEFAULT_FILENAME)
    rules = load_intent(intent_path) if (intent or os.path.isfile(intent_path)) else []
    result.intent_rules = len(rules)
    custom_fields = extra_fields(rules)

    taint_sources: list[tuple[str, str]] = []
    ignored_lines: dict[str, set[int]] = {}
    file: SourceFile
    for file in iter_source_files(root, **kwargs):
        try:
            text = read_text(file)
        except OSError:
            continue
        marked = {i for i, ln in enumerate(text.splitlines(), 1) if INLINE_IGNORE.search(ln)}
        if marked:
            ignored_lines[file.relpath] = marked
        result.secret_findings.extend(secrets.scan_text(file.relpath, text))
        result.routes.extend(extract_routes(file.relpath, text))
        result.sink_findings.extend(scan_sinks(file.relpath, text))
        result.idor_findings.extend(analyze_access_control(file.relpath, text))
        result.misconfig_findings.extend(scan_misconfig(file.relpath, text))
        result.logging_findings.extend(scan_logging(file.relpath, text))
        result.logic_findings.extend(analyze_business_logic(file.relpath, text, custom_fields))
        if file.relpath.endswith((".py", *JS_EXTENSIONS)):
            taint_sources.append((file.relpath, text))
        if is_lockfile(file.relpath):
            result.dependencies.extend(parse_dependencies(file.relpath, text))

    # Taint runs once over the whole project so flow can cross files.
    result.taint_findings = analyze_taint_project(taint_sources)
    result.route_findings = route_findings(result.routes)
    result.logic_findings.extend(authz_outliers(result.routes))
    result.logic_findings.extend(evaluate_intent(rules, result.routes, result.idor_findings))
    _dedupe_sinks_superseded_by_taint(result)
    _apply_inline_ignores(result, ignored_lines)

    if check_osv and result.dependencies:
        _run_osv(result, osv_client or OsvClient())
    elif result.dependencies:
        result.osv_note = "Known-vulnerability lookup skipped (--no-osv)."

    return result


def _apply_inline_ignores(result: ScanResult, ignored: dict[str, set[int]]) -> None:
    """Drop findings reported on a line carrying a `secureagent: ignore` comment."""
    if not ignored:
        return

    def kept(relpath: str, line: int) -> bool:
        return line not in ignored.get(relpath, ())

    before = result.total_findings
    result.secret_findings = [f for f in result.secret_findings if kept(f.relpath, f.line)]
    result.sink_findings = [f for f in result.sink_findings if kept(f.relpath, f.line)]
    result.taint_findings = [f for f in result.taint_findings if kept(f.relpath, f.line)]
    result.idor_findings = [f for f in result.idor_findings if kept(f.relpath, f.line)]
    result.misconfig_findings = [f for f in result.misconfig_findings if kept(f.relpath, f.line)]
    result.logging_findings = [f for f in result.logging_findings if kept(f.relpath, f.line)]
    result.logic_findings = [f for f in result.logic_findings if kept(f.relpath, f.line)]
    result.route_findings = [
        f for f in result.route_findings if kept(f.route.relpath, f.route.line)
    ]
    result.inline_ignored = before - result.total_findings


def _dedupe_sinks_superseded_by_taint(result: ScanResult) -> None:
    # A taint finding (input reaches the sink) is the actionable version of a bare
    # sink at the same location; drop the duplicate bare sink to cut noise.
    taint_keys = {(f.relpath, f.line, f.vuln_type) for f in result.taint_findings}
    result.sink_findings = [
        s for s in result.sink_findings if (s.relpath, s.line, s.category) not in taint_keys
    ]


def _run_osv(result: ScanResult, client: OsvClient) -> None:
    try:
        vulns_by_key = client.query(result.dependencies)
    except OsvError as exc:
        result.osv_note = f"Known-vulnerability lookup unavailable: {exc}"
        return
    for dep in result.dependencies:
        vulns = vulns_by_key.get(dep.key)
        if vulns:
            result.dependency_findings.append(
                DependencyFinding(
                    dependency=dep,
                    vulns=vulns,
                    severity=_worst_severity(vulns),
                    confidence=0.9,  # the lockfile declares this exact affected version
                )
            )
