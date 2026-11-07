"""Run the static analysers over an ingested source tree and collect findings."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace

from app.analysis import secrets
from app.analysis.access_control import IdorFinding, analyze_access_control
from app.analysis.authz_matrix import authz_outliers
from app.analysis.business_logic import LogicFinding, analyze_business_logic
from app.analysis.dependencies import Dependency, is_lockfile, parse_dependencies
from app.analysis.exploit_intel import ExploitIntelClient, priority
from app.analysis.gitignore import GitIgnore
from app.analysis.hardening import LOCKS, MANIFESTS, recommend
from app.analysis.ingest import (
    IngestStats,
    SourceFile,
    iter_source_files,
    load_ignore_file,
    read_text,
)
from app.analysis.intent import (
    DEFAULT_FILENAME,
    Profile,
    evaluate_intent,
    extra_fields,
    load_intent,
    load_profile,
)
from app.analysis.logging_checks import LoggingFinding, scan_logging
from app.analysis.misconfig import CATEGORY as MISCONFIG_CATEGORY
from app.analysis.misconfig import MisconfigFinding, scan_misconfig
from app.analysis.misconfig import MisconfigFinding as _MisconfigFinding
from app.analysis.openapi_spec import (
    SPEC_HANDLERS,
    SPEC_OPERATIONS,
    SpecOperation,
    locate_handler,
    parse_django_urls,
    parse_spec,
)
from app.analysis.osv import OsvClient, OsvError, Vuln
from app.analysis.reachability import imported_modules, is_imported
from app.analysis.recon import ApplicationModel
from app.analysis.routes import (
    Route,
    RouteFinding,
    apply_include_guards,
    extract_routes,
    route_findings,
)
from app.analysis.secrets import SecretFinding
from app.analysis.sinks import SinkFinding, scan_sinks
from app.analysis.supply_chain import (
    DeclaredPackage,
    RegistryClient,
    declared_packages,
    typosquat_target,
)
from app.analysis.suppressions import FILENAME as SUPPRESSIONS_FILENAME
from app.analysis.suppressions import Suppression
from app.analysis.suppressions import load as load_suppressions
from app.analysis.taint import JS_EXTENSIONS, TaintFinding, analyze_taint_project
from app.analysis.taint_specs import FILENAME as TAINT_SPEC_FILENAME
from app.analysis.taint_specs import TaintSpec
from app.analysis.taint_specs import active as taint_spec_active
from app.analysis.taint_specs import load as load_taint_spec
from app.analysis.workflow import analyze_workflow
from app.schemas.report import HardeningSummary

PRIORITY_ORDER = {"urgent": 0, "high": 1, "normal": 2, "low": 3}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4, "informational": 5}

# `# secureagent: ignore`, `// secureagent:ignore`, ... on the line a finding is reported at.
INLINE_IGNORE = re.compile(r"secureagent:\s*ignore", re.IGNORECASE)


@dataclass(frozen=True)
class DependencyFinding:
    dependency: Dependency
    vulns: list[Vuln]
    severity: str
    confidence: float
    kev: bool = False  # a CVE of this package is on CISA's Known Exploited Vulnerabilities list
    epss: float | None = None  # highest FIRST EPSS probability among its CVEs (None = unknown)
    imported: bool | None = None  # first-party code imports it (None = cannot tell)

    @property
    def malicious(self) -> bool:
        return any(v.malicious for v in self.vulns)

    @property
    def title(self) -> str:
        d = self.dependency
        kind = "Malicious package" if self.malicious else "Vulnerable dependency"
        return f"{kind}: {d.name} {d.version}"

    @property
    def priority(self) -> str:
        if self.malicious:
            return "urgent"
        return priority(self.kev, self.epss, self.imported, self.severity)

    @property
    def priority_reason(self) -> str:
        parts = []
        if self.malicious:
            parts.append("OSV lists this package as malicious")
        if self.kev:
            parts.append("on CISA KEV: exploited in the wild")
        if self.epss is not None:
            parts.append(f"EPSS {self.epss:.1%} chance of exploitation in 30 days")
        if self.imported is True:
            parts.append("imported by first-party code")
        elif self.imported is False:
            parts.append("not imported directly by first-party code (may be transitive)")
        return "; ".join(parts) or "no exploit intelligence available"

    @property
    def worst_cvss(self) -> Vuln | None:
        """The advisory with the highest *computed* CVSS score, if any publishes a vector."""
        scored = [v for v in self.vulns if v.cvss_score is not None]
        return max(scored, key=lambda v: v.cvss_score) if scored else None


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
    superseded: int = 0  # generic unguarded-route findings replaced by a more specific one
    app_model: ApplicationModel = field(default_factory=ApplicationModel)
    suppressions: list[Suppression] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    dependency_findings: list[DependencyFinding] = field(default_factory=list)
    osv_note: str | None = None
    inline_ignored: int = 0  # findings hidden by `secureagent: ignore` comments (always reported)
    stats: IngestStats = field(default_factory=IngestStats)
    profile: Profile | None = None  # declared application profile (ADR-045)
    hardening: HardeningSummary | None = None  # guidance, never counted as findings
    manifests: list[str] = field(default_factory=list)  # relpaths of dependency manifests
    lockfiles: list[str] = field(default_factory=list)  # relpaths of lockfiles / pinned lists

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
            key=lambda f: (
                PRIORITY_ORDER[f.priority],
                SEVERITY_ORDER.get(f.severity, 9),
                -(f.epss or 0.0),
                f.dependency.name,
            ),
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
    suppressions: str | None = None,
    intel_client: ExploitIntelClient | None = None,
    registry_client: RegistryClient | None = None,
) -> ScanResult:
    """Ingest ``root`` (read-only) and run all static analysers (see ``_scan_repo``).

    OpenAPI documents are read first so spec-first handlers (``operationId``) are known to every
    analyser; the discovered names live in a context variable for the duration of the scan only."""
    ops: list[SpecOperation] = []
    probe_kwargs: dict = {"stats": IngestStats(), "exclude": [*load_ignore_file(root), *exclude]}
    url_views: set[str] = set()
    for f in iter_source_files(root, **probe_kwargs):
        low = f.relpath.lower()
        if f.size > 2_000_000:
            continue
        try:
            if low.endswith((".yml", ".yaml", ".json")):
                ops.extend(parse_spec(f.relpath, read_text(f)))
            elif low.endswith("urls.py"):
                url_views |= parse_django_urls(read_text(f))
        except OSError:
            continue
    handlers = SPEC_HANDLERS.set(frozenset({o.function for o in ops} | url_views))
    operations = SPEC_OPERATIONS.set(tuple(ops))
    spec_path = os.path.join(str(root), TAINT_SPEC_FILENAME)
    spec = load_taint_spec(spec_path) if os.path.isfile(spec_path) else TaintSpec()
    try:
        with taint_spec_active(spec):
            return _scan_repo(
                root,
                max_files=max_files,
                check_osv=check_osv,
                osv_client=osv_client,
                exclude=exclude,
                intent=intent,
                suppressions=suppressions,
                intel_client=intel_client,
                registry_client=registry_client,
            )
    finally:
        SPEC_OPERATIONS.reset(operations)
        SPEC_HANDLERS.reset(handlers)


def _scan_repo(
    root: str,
    *,
    max_files: int | None = None,
    check_osv: bool = True,
    osv_client: OsvClient | None = None,
    exclude: Sequence[str] = (),
    intent: str | None = None,
    suppressions: str | None = None,
    intel_client: ExploitIntelClient | None = None,
    registry_client: RegistryClient | None = None,
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
    result.profile = load_profile(intent_path) if (intent or os.path.isfile(intent_path)) else None
    custom_fields = extra_fields(rules)
    supp_path = suppressions or os.path.join(str(root), SUPPRESSIONS_FILENAME)
    if suppressions or os.path.isfile(supp_path):
        result.suppressions = load_suppressions(supp_path)

    gitignore = GitIgnore.from_root(root)
    taint_sources: list[tuple[str, str]] = []
    declared: list[DeclaredPackage] = []
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
        found = secrets.scan_text(file.relpath, text)
        if found and gitignore and gitignore.is_ignored(file.relpath):
            found = [replace(f, gitignored=True) for f in found]
        result.secret_findings.extend(found)
        result.app_model.absorb_file(file.relpath, text)
        result.routes.extend(extract_routes(file.relpath, text))
        result.sink_findings.extend(scan_sinks(file.relpath, text))
        result.idor_findings.extend(analyze_access_control(file.relpath, text))
        result.misconfig_findings.extend(scan_misconfig(file.relpath, text))
        result.logging_findings.extend(scan_logging(file.relpath, text))
        result.logic_findings.extend(analyze_business_logic(file.relpath, text, custom_fields))
        result.logic_findings.extend(analyze_workflow(file.relpath, text))
        if file.relpath.endswith((".py", *JS_EXTENSIONS)):
            taint_sources.append((file.relpath, text))
        if is_lockfile(file.relpath):
            result.dependencies.extend(parse_dependencies(file.relpath, text))
        declared.extend(declared_packages(file.relpath, text))
        base = file.relpath.rsplit("/", 1)[-1].lower()
        if base in MANIFESTS:
            result.manifests.append(file.relpath)
        if base in LOCKS or is_lockfile(file.relpath):
            result.lockfiles.append(file.relpath)

    # Taint runs once over the whole project so flow can cross files.
    result.taint_findings = analyze_taint_project(taint_sources)
    result.routes = apply_include_guards(result.routes, taint_sources)
    for op in SPEC_OPERATIONS.get():  # spec-first routes: no decorator, the document is the table
        where = locate_handler(op, taint_sources)
        if where is not None:
            result.routes.append(
                Route(
                    op.method.upper(),
                    op.path,
                    "openapi",
                    where[0],
                    where[1],
                    op.function,
                    op.secured,
                    "openapi security" if op.secured else None,
                )
            )
    result.route_findings = route_findings(result.routes)
    for route in result.routes:
        result.app_model.absorb_route_path(route.path)
    for dep in result.dependencies:
        result.app_model.absorb_dependency(dep.name, dep.relpath)
    result.logic_findings.extend(authz_outliers(result.routes))
    result.logic_findings.extend(evaluate_intent(rules, result.routes, result.idor_findings))
    _dedupe_sinks_superseded_by_taint(result)
    _dedupe_route_findings(result)
    _apply_inline_ignores(result, ignored_lines)

    # The live feeds (KEV/EPSS, registry existence) follow the OSV switch; with an injected OSV
    # client (tests, offline callers) they run only when injected too.
    if check_osv and osv_client is None:
        intel_client = intel_client or ExploitIntelClient()
        registry_client = registry_client or RegistryClient()
    _check_declared_packages(result, declared, registry_client if check_osv else None)
    if check_osv and result.dependencies:
        _run_osv(result, osv_client or OsvClient())
        _annotate_dependencies(result, intel_client, imported_modules(taint_sources))
    elif result.dependencies:
        result.osv_note = "Known-vulnerability lookup skipped (--no-osv)."

    # After OSV, so dependency findings are final; ignores are already applied above.
    result.hardening = recommend(result, result.profile)
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


def _dedupe_route_findings(result: ScanResult) -> None:
    """The generic "endpoint without visible authorization" finding is superseded by a more
    specific finding on the same route (an unguarded sibling, or a declared require_auth rule)."""
    specific = {
        (f.relpath, f.line)
        for f in result.logic_findings
        if f.category == "inconsistent_authorization"
        or (f.category == "intent_violation" and "[require_auth]" in f.rule)
    }
    kept = [f for f in result.route_findings if (f.route.relpath, f.route.line) not in specific]
    result.superseded = len(result.route_findings) - len(kept)
    result.route_findings = kept


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
                    severity=(
                        "critical" if any(v.malicious for v in vulns) else _worst_severity(vulns)
                    ),
                    confidence=0.9,  # the lockfile declares this exact affected version
                )
            )


def _check_declared_packages(
    result: ScanResult, declared: list[DeclaredPackage], registry: RegistryClient | None
) -> None:
    """Typosquat names (offline) and names the public registry does not know (online)."""

    def add(category: str, pkg: DeclaredPackage, rule: str) -> None:
        sev, conf = MISCONFIG_CATEGORY[category][3], MISCONFIG_CATEGORY[category][4]
        result.misconfig_findings.append(
            _MisconfigFinding(category, rule, sev, conf, pkg.relpath, pkg.line, pkg.name)
        )

    for pkg in declared:
        target = typosquat_target(pkg.ecosystem, pkg.name)
        if target:
            add("typosquat_package", pkg, f"{pkg.name} is one edit away from {target}")
    if registry is not None and declared:
        for pkg in registry.missing(declared):
            add("unregistered_package", pkg, f"{pkg.ecosystem} has no package named {pkg.name}")


def _annotate_dependencies(
    result: ScanResult,
    intel_client: ExploitIntelClient | None,
    imports: tuple[set[str], set[str], bool, bool],
) -> None:
    """Attach KEV / EPSS / import reachability to dependency findings (never drops one)."""
    intel = None
    if intel_client is not None and result.dependency_findings:
        intel = intel_client.lookup(
            {v.cve for f in result.dependency_findings for v in f.vulns if v.cve}
        )
        if intel.note:
            result.osv_note = " ".join(n for n in (result.osv_note, intel.note) if n)
    annotated = []
    for f in result.dependency_findings:
        cves = {v.cve for v in f.vulns if v.cve}
        scores = [intel.epss[c] for c in cves if intel and c in intel.epss]
        annotated.append(
            replace(
                f,
                kev=bool(intel and cves & intel.kev),
                epss=max(scores) if scores else None,
                imported=is_imported(f.dependency, imports),
            )
        )
    result.dependency_findings = annotated
