"""Structured input for report rendering. The Report Agent builds this from persisted
audit data; templates only format it and never invent values."""

from collections import Counter
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import FindingStatus, Severity

SEVERITY_ORDER = list(Severity)  # critical → informational
NO_CVE = "Not applicable / no specific CVE identified."
NO_CVSS = "CVSS not determined."


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
        return sorted(kept, key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.confidence))

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
