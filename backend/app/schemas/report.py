"""Structured input for report rendering. The Report Agent builds this from persisted
audit data; templates only format it and never invent values."""

import re
from collections import Counter
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import FindingStatus, Severity

SEVERITY_ORDER = list(Severity)  # critical → informational
NO_CVE = "Not applicable / no specific CVE identified."
NO_CVSS = "CVSS not determined."

# Most-trusted status first: a confirmed finding outranks a suspicion of equal severity.
STATUS_RANK = {
    FindingStatus.CONFIRMED: 0,
    FindingStatus.LIKELY: 1,
    FindingStatus.SUSPICIOUS: 2,
    FindingStatus.INFORMATIONAL: 3,
    FindingStatus.FALSE_POSITIVE: 4,
}
RISK_LABELS = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Moderate",
    Severity.LOW: "Low",
    Severity.INFORMATIONAL: "Informational",
}
_LINE_SUFFIX = re.compile(r"^(?P<file>.*?):\d+$")
_ACRONYMS = {"sql", "ssrf", "tls", "idor", "xxe", "xss", "jwt", "csrf", "cors", "cwe", "cve", "api"}


def type_label(finding_type: str) -> str:
    """'sql_injection' -> 'SQL injection'; keeps well-known acronyms upper-case."""
    words = [w.upper() if w in _ACRONYMS else w for w in finding_type.split("_")]
    label = " ".join(words)
    return label[:1].upper() + label[1:]


class CvssScore(BaseModel):
    score: float = Field(ge=0, le=10)
    vector: str | None = None
    version: str | None = None


class ReportFinding(BaseModel):
    title: str
    type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    status: FindingStatus
    status_reason: str | None = None
    endpoint: str
    parameter: str | None = None
    description: str | None = None
    impact: str | None = None
    evidence: str | None = None
    validation_method: str | None = None
    owasp_category: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: CvssScore | None = None
    remediation: str | None = None
    sources: list[str] = []

    @property
    def cve_display(self) -> str:
        return self.cve or NO_CVE

    @property
    def cvss_display(self) -> str:
        if self.cvss is None:
            return NO_CVSS
        parts = [f"{self.cvss.score:.1f}"]
        if self.cvss.version:
            parts.append(f"(CVSS v{self.cvss.version})")
        if self.cvss.vector:
            parts.append(self.cvss.vector)
        return " ".join(parts)


class FindingGroup(BaseModel):
    """All findings of one type, consolidated so the reader fixes a class of problem once."""

    type: str
    label: str
    count: int
    worst_severity: Severity
    best_status: FindingStatus
    statuses: dict[str, int]
    locations: list[str]
    cwe: str | None = None
    owasp_category: str | None = None
    remediation: str | None = None
    max_confidence: float


class TimelineEntry(BaseModel):
    stage: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    note: str | None = None


class ReportContext(BaseModel):
    audit_id: str
    audit_status: str
    is_demo: bool = False
    started_at: datetime | None = None
    completed_at: datetime | None = None
    generated_at: datetime

    target_name: str
    target_url: str
    target_description: str | None = None
    scope: dict = {}

    authorized_by: str
    authorized_at: datetime | None = None
    authorization_statement: str

    executive_summary: str | None = None
    methodology: list[str] = []
    technologies: list[str] = []
    endpoints: list[str] = []
    api_endpoints: list[str] = []
    forms: list[str] = []
    parameters: list[str] = []
    interesting_paths: list[str] = []
    findings: list[ReportFinding] = []
    limitations: list[str] = []
    timeline: list[TimelineEntry] = []

    # --- derived views (deterministic; templates use these) ---

    @property
    def reportable_findings(self) -> list[ReportFinding]:
        """Everything except false positives, most severe first."""
        kept = [f for f in self.findings if f.status is not FindingStatus.FALSE_POSITIVE]
        return sorted(
            kept,
            key=lambda f: (
                SEVERITY_ORDER.index(f.severity),
                STATUS_RANK[f.status],
                -f.confidence,
                f.endpoint,
                f.title,
            ),
        )

    @property
    def risk_rating(self) -> str:
        """Highest severity among reportable findings (never inflated beyond the evidence)."""
        counts = self.severity_counts
        for sev in SEVERITY_ORDER:
            if counts[sev]:
                return RISK_LABELS[sev]
        return "None identified"

    @property
    def risk_basis(self) -> str:
        kept = self.reportable_findings
        if not kept:
            return "No reportable findings within the tested scope; see Limitations."
        by_status = Counter(f.status for f in kept)
        parts = ", ".join(
            f"{by_status[s]} {s.value}"
            for s in (
                FindingStatus.CONFIRMED,
                FindingStatus.LIKELY,
                FindingStatus.SUSPICIOUS,
                FindingStatus.INFORMATIONAL,
            )
            if by_status[s]
        )
        caveat = (
            ""
            if by_status[FindingStatus.CONFIRMED] == len(kept)
            else " Findings not marked confirmed are unverified indicators."
        )
        return f"Highest severity among {len(kept)} finding(s) ({parts}).{caveat}"

    @property
    def finding_groups(self) -> list[FindingGroup]:
        """Findings consolidated by type, most urgent first (severity, then trust, then size)."""
        buckets: dict[str, list[ReportFinding]] = {}
        for f in self.reportable_findings:
            buckets.setdefault(f.type, []).append(f)
        groups = []
        for ftype, items in buckets.items():
            groups.append(
                FindingGroup(
                    type=ftype,
                    label=type_label(ftype),
                    count=len(items),
                    worst_severity=min(
                        items, key=lambda f: SEVERITY_ORDER.index(f.severity)
                    ).severity,
                    best_status=min(items, key=lambda f: STATUS_RANK[f.status]).status,
                    statuses=dict(Counter(f.status.value for f in items)),
                    locations=sorted({f.endpoint for f in items}),
                    cwe=next((f.cwe for f in items if f.cwe), None),
                    owasp_category=next(
                        (f.owasp_category for f in items if f.owasp_category), None
                    ),
                    remediation=next((f.remediation for f in items if f.remediation), None),
                    max_confidence=max(f.confidence for f in items),
                )
            )
        groups.sort(
            key=lambda g: (
                SEVERITY_ORDER.index(g.worst_severity),
                STATUS_RANK[g.best_status],
                -g.count,
                g.type,
            )
        )
        return groups

    def hotspots(self, n: int = 5) -> list[tuple[str, int]]:
        """Files (or endpoints) carrying the most findings; where a fix pays off most."""
        counts: Counter[str] = Counter()
        for f in self.reportable_findings:
            m = _LINE_SUFFIX.match(f.endpoint)
            counts[m.group("file") if m else f.endpoint] += 1
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    @property
    def with_cve(self) -> list[ReportFinding]:
        return [f for f in self.reportable_findings if f.cve]

    @property
    def with_cvss(self) -> list[ReportFinding]:
        return [f for f in self.reportable_findings if f.cvss is not None]

    @property
    def false_positives(self) -> list[ReportFinding]:
        return [f for f in self.findings if f.status is FindingStatus.FALSE_POSITIVE]

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = Counter(f.severity for f in self.reportable_findings)
        return {s: counts.get(s, 0) for s in SEVERITY_ORDER}

    @property
    def status_counts(self) -> dict[FindingStatus, int]:
        counts = Counter(f.status for f in self.findings)
        return {s: counts.get(s, 0) for s in FindingStatus}

    def grouped_by(self, attr: str) -> dict[str, list[ReportFinding]]:
        groups: dict[str, list[ReportFinding]] = {}
        for f in self.reportable_findings:
            groups.setdefault(getattr(f, attr) or "Unmapped", []).append(f)
        return dict(sorted(groups.items()))

    def default_executive_summary(self) -> str:
        """Deterministic summary used when no AI narrative is available."""
        kept = self.reportable_findings
        if not kept:
            return (
                f"The audit of {self.target_name} did not identify reportable security "
                "findings within the tested scope. This does not prove the absence of "
                "vulnerabilities; see Limitations."
            )
        sev = self.severity_counts
        top = ", ".join(f"{n} {s.value}" for s, n in sev.items() if n)
        confirmed = self.status_counts[FindingStatus.CONFIRMED]
        return (
            f"The audit of {self.target_name} identified {len(kept)} reportable finding(s) "
            f"({top}), of which {confirmed} were confirmed by safe validation. "
            f"{len(self.false_positives)} scanner alert(s) were rejected as false positives."
        )
