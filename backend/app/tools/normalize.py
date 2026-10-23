"""Map raw scanner alerts to suspected findings. CVE/CVSS copied only from tool metadata."""

from __future__ import annotations

import hashlib
import re

from app.core.enums import Severity
from app.schemas.pipeline import RawToolAlert, SuspectedFinding

_OWASP = {
    "xss": ("A03:2021 Injection", "CWE-79"),
    "sql": ("A03:2021 Injection", "CWE-89"),
    "inject": ("A03:2021 Injection", "CWE-74"),
    "csrf": ("A01:2021 Broken Access Control", "CWE-352"),
    "cors": ("A05:2021 Security Misconfiguration", "CWE-942"),
    "cookie": ("A05:2021 Security Misconfiguration", "CWE-614"),
    "header": ("A05:2021 Security Misconfiguration", "CWE-693"),
    "hsts": ("A05:2021 Security Misconfiguration", "CWE-319"),
    "csp": ("A05:2021 Security Misconfiguration", "CWE-693"),
    "disclos": ("A05:2021 Security Misconfiguration", "CWE-200"),
    "path traversal": ("A01:2021 Broken Access Control", "CWE-22"),
    "redirect": ("A01:2021 Broken Access Control", "CWE-601"),
    "ssrf": ("A10:2021 SSRF", "CWE-918"),
    "auth": ("A07:2021 Identification and Authentication Failures", "CWE-287"),
}

_SEV = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}

_REMEDIATION = {
    "A03:2021 Injection": "Validate and encode untrusted input; use parameterised APIs.",
    "A05:2021 Security Misconfiguration": "Set the missing control (header, cookie flag, CORS policy) in the application or reverse proxy.",
    "A01:2021 Broken Access Control": "Enforce authorization on the server for every object and action.",
    "A07:2021 Identification and Authentication Failures": "Use a proven authentication library and harden session handling.",
    "A10:2021 SSRF": "Allow-list outbound destinations; do not fetch URLs supplied by clients.",
}


def _type_from_name(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return (slug or "scanner_alert")[:80]


def _map_standards(alert: RawToolAlert) -> tuple[str | None, str | None]:
    extra = alert.extra or {}
    owasp = extra.get("owasp")
    blob = f"{alert.name} {alert.description}".lower()
    cwe = alert.cwe
    if not owasp:
        for key, (ow, cw) in _OWASP.items():
            if key in blob:
                owasp, cwe = ow, (cwe or cw)
                break
    if not owasp:
        owasp = "A05:2021 Security Misconfiguration"
    if cwe and not str(cwe).upper().startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return owasp, cwe


def _cve(raw: str | None) -> str | None:
    if not raw:
        return None
    m = re.search(r"CVE-\d{4}-\d+", raw, re.I)
    return m.group(0).upper() if m else None


def fingerprint_alert(audit_id: str, alert: RawToolAlert) -> str:
    basis = f"{audit_id}|{_type_from_name(alert.name)}|{alert.url}|{alert.parameter or ''}"
    return hashlib.sha256(basis.encode()).hexdigest()


def to_suspected(audit_id: str, alerts: list[RawToolAlert]) -> list[SuspectedFinding]:
    out: list[SuspectedFinding] = []
    seen: set[str] = set()
    for alert in alerts:
        fp = fingerprint_alert(audit_id, alert)
        if fp in seen:
            # Same fingerprint from a second tool: merge sources later in the validator.
            existing = next((f for f in out if f.id == fp), None)
            if existing and alert.source not in existing.sources:
                existing.sources.append(alert.source)
                existing.confidence = min(0.85, existing.confidence + 0.15)
                if alert.cve and not existing.cve:
                    existing.cve = _cve(alert.cve)
                if alert.cvss and not existing.cvss:
                    existing.cvss = alert.cvss
            continue
        seen.add(fp)
        owasp, cwe = _map_standards(alert)
        sev = _SEV.get(alert.severity.lower(), Severity.INFORMATIONAL)
        out.append(
            SuspectedFinding(
                id=fp,
                title=alert.name[:255],
                type=_type_from_name(alert.name),
                endpoint=alert.url[:2048],
                parameter=alert.parameter,
                severity=sev,
                confidence=0.55 if alert.source in {"zap", "nuclei"} else 0.45,
                description=alert.description[:4000],
                evidence=alert.evidence[:1000],
                owasp_category=owasp,
                cwe=cwe,
                cve=_cve(alert.cve),
                cvss=alert.cvss,
                sources=[alert.source],
                remediation=_REMEDIATION.get(
                    owasp or "", "Review the finding and apply the relevant control."
                ),
            )
        )
    return out
