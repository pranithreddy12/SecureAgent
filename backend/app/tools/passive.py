"""Deterministic checks on recon data (headers, cookies). No extra requests."""

from __future__ import annotations

from app.schemas.pipeline import RawToolAlert, ReconResult

_SECURITY_HEADERS = (
    ("strict-transport-security", "missing_hsts", "A05:2021 Security Misconfiguration", "CWE-319"),
    ("content-security-policy", "missing_csp", "A05:2021 Security Misconfiguration", "CWE-693"),
    ("x-content-type-options", "missing_xcto", "A05:2021 Security Misconfiguration", "CWE-693"),
    ("x-frame-options", "missing_xfo", "A05:2021 Security Misconfiguration", "CWE-1021"),
)


def passive_alerts(recon: ReconResult) -> list[RawToolAlert]:
    headers = {k.lower(): v for k, v in recon.headers.items()}
    out: list[RawToolAlert] = []
    for header, ftype, owasp, cwe in _SECURITY_HEADERS:
        if header not in headers:
            out.append(
                RawToolAlert(
                    source="passive",
                    name=f"Missing {header} header",
                    url=recon.target,
                    severity="low",
                    description=f"The response from {recon.target} did not include {header}.",
                    evidence=f"Observed headers: {', '.join(sorted(headers)[:12]) or '(none)'}",
                    cwe=cwe,
                    extra={"type": ftype, "owasp": owasp},
                )
            )
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(
            RawToolAlert(
                source="passive",
                name="CORS allows any origin with credentials",
                url=recon.target,
                severity="high",
                description="Access-Control-Allow-Origin is * while credentials are allowed.",
                evidence=f"ACAO={acao}; ACAC={acac}",
                cwe="CWE-942",
                extra={
                    "type": "cors_misconfiguration",
                    "owasp": "A05:2021 Security Misconfiguration",
                },
            )
        )
    set_cookie = headers.get("set-cookie", "")
    if set_cookie and "secure" not in set_cookie.lower():
        out.append(
            RawToolAlert(
                source="passive",
                name="Cookie without Secure flag",
                url=recon.target,
                severity="medium",
                description="A Set-Cookie header was observed without the Secure flag.",
                evidence=set_cookie[:200],
                cwe="CWE-614",
                extra={"type": "insecure_cookie", "owasp": "A05:2021 Security Misconfiguration"},
            )
        )
    server = headers.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        out.append(
            RawToolAlert(
                source="passive",
                name="Server version disclosed",
                url=recon.target,
                severity="informational",
                description="The Server header includes a version token.",
                evidence=server[:120],
                cwe="CWE-200",
                extra={
                    "type": "information_disclosure",
                    "owasp": "A05:2021 Security Misconfiguration",
                },
            )
        )
    return out
