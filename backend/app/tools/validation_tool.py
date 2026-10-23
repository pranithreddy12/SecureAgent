"""Non-destructive evidence collection (ADR-003). Never sends exploit payloads."""

from __future__ import annotations

import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.schemas.pipeline import SuspectedFinding, ValidationResult
from app.tools.http import fetch
from app.tools.policy import PolicyError, RequestContext

# Unique inert token; alphanumeric only so it cannot be interpreted as markup or SQL.
_MARKER_PREFIX = "saevd"


def _marker() -> str:
    return _MARKER_PREFIX + secrets.token_hex(6)


def _with_query(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[key] = value
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def validate_finding(finding: SuspectedFinding, ctx: RequestContext) -> ValidationResult:
    kind = _category(finding)
    if kind == "reflection":
        return _reflection(finding, ctx)
    if kind == "configuration":
        return _configuration(finding, ctx)
    if kind == "disclosure":
        return _disclosure(finding, ctx)
    if kind == "injection_indicator":
        return ValidationResult(
            finding_id=finding.id,
            validated=None,
            confidence=finding.confidence,
            evidence="Injection indicators are not re-tested; scanner evidence is left as recorded.",
            validation_method="no_retest_injection",
            risk_notes="No new requests were sent. Status stays below confirmed.",
        )
    if kind == "component":
        return _disclosure(finding, ctx)
    return ValidationResult(
        finding_id=finding.id,
        validated=None,
        confidence=finding.confidence,
        evidence="",
        validation_method="no safe validation strategy",
        risk_notes="No non-destructive strategy exists for this finding type.",
    )


def _category(finding: SuspectedFinding) -> str:
    blob = f"{finding.type} {finding.title}".lower()
    if any(k in blob for k in ("xss", "reflect", "cross-site scripting")):
        return "reflection"
    if any(k in blob for k in ("header", "hsts", "csp", "cookie", "cors", "xcto", "xfo")):
        return "configuration"
    if any(k in blob for k in ("disclos", "server version", "directory listing", "robots")):
        return "disclosure"
    if any(k in blob for k in ("sql", "inject", "ssti", "command")):
        return "injection_indicator"
    if any(k in blob for k in ("outdated", "cve-", "component", "jquery", "version")):
        return "component"
    return "other"


def _reflection(finding: SuspectedFinding, ctx: RequestContext) -> ValidationResult:
    marker = _marker()
    param = finding.parameter or "secureagent"
    url = _with_query(finding.endpoint, param, marker)
    try:
        resp = fetch(url, ctx)
    except PolicyError as exc:
        return ValidationResult(
            finding_id=finding.id,
            validated=None,
            confidence=0.0,
            evidence=str(exc),
            validation_method="inert_marker_reflection",
            risk_notes="Request blocked by policy.",
        )
    body = resp.body.decode("utf-8", errors="replace")
    reflected = marker in body
    ctx_note = "html body"
    if reflected and (f"'{marker}'" in body or f'"{marker}"' in body):
        ctx_note = "quoted attribute-like context"
    return ValidationResult(
        finding_id=finding.id,
        validated=reflected,
        confidence=0.7 if reflected else 0.5,
        evidence=f"Inert marker {'was' if reflected else 'was not'} reflected ({ctx_note}).",
        validation_method="inert_marker_reflection",
    )


def _configuration(finding: SuspectedFinding, ctx: RequestContext) -> ValidationResult:
    try:
        resp = fetch(finding.endpoint, ctx)
    except PolicyError as exc:
        return ValidationResult(
            finding_id=finding.id,
            validated=None,
            evidence=str(exc),
            validation_method="header_refetch",
        )
    headers = {k.lower(): v for k, v in resp.headers.items()}
    blob = f"{finding.type} {finding.title}".lower()
    present = True
    if "hsts" in blob:
        present = "strict-transport-security" in headers
    elif "csp" in blob:
        present = "content-security-policy" in headers
    elif "xcto" in blob or "content-type-options" in blob:
        present = "x-content-type-options" in headers
    elif "xfo" in blob or "frame-options" in blob:
        present = "x-frame-options" in headers or "content-security-policy" in headers
    elif "cors" in blob:
        present = headers.get("access-control-allow-origin") != "*"
    elif "cookie" in blob:
        sc = headers.get("set-cookie", "")
        present = (not sc) or ("secure" in sc.lower())
    # validated True means "the issue is real" → missing header => validated True
    issue_still_present = not present
    return ValidationResult(
        finding_id=finding.id,
        validated=issue_still_present,
        confidence=0.8,
        evidence=f"Re-fetched {resp.url} status={resp.status}.",
        validation_method="header_refetch",
    )


def _disclosure(finding: SuspectedFinding, ctx: RequestContext) -> ValidationResult:
    try:
        resp = fetch(finding.endpoint, ctx)
    except PolicyError as exc:
        return ValidationResult(
            finding_id=finding.id,
            validated=None,
            evidence=str(exc),
            validation_method="path_refetch",
        )
    excerpt = resp.body[:200].decode("utf-8", errors="replace")
    return ValidationResult(
        finding_id=finding.id,
        validated=resp.status < 400,
        confidence=0.6,
        evidence=f"status={resp.status} excerpt={excerpt!r}",
        validation_method="path_refetch",
    )
