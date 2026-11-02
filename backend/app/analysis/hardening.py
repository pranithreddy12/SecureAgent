"""Context-aware hardening recommendations (ADR-045).

Findings say what is broken. Recommendations say which protective controls an application of this
kind should probably have, given what the scanner saw and what the developer *declared* about it
(``profile`` in secureagent-intent.json). A recommendation is guidance, never a finding: it has no
severity and never touches counts, SARIF, baselines, gating, chains or fixes.

Pure functions over a finished ``ScanResult``: no I/O, no network, no LLM, deterministic output.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from app.analysis.intent import USER_BANDS, Profile
from app.schemas.report import HardeningSummary, Recommendation, RecommendationEvidence

if TYPE_CHECKING:
    from app.analysis.scanner import ScanResult

MANIFESTS = frozenset({"package.json", "pyproject.toml", "pipfile"})
LOCKS = frozenset(
    {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "pipfile.lock", "uv.lock"}
)
_LOGIN = re.compile(r"login|signin|sign-in|token|auth/|session", re.I)
_FRAMEWORKS = {"Flask", "FastAPI", "Django", "Starlette", "Express", "Next.js", "NestJS"}
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
_AUTHZ_TYPES = ("idor", "missing_function_level_authorization", "inconsistent_authorization")
_MAX_EVIDENCE = 5
_ESCALATE = {"HR-HEADERS", "HR-AUDIT-LOG", "HR-MONITORING"}
_CONSULT = "review with whoever owns compliance."


class Need(tuple):
    """A rule that would have fired but for missing profile fields."""


class Signals:
    def __init__(self, result: ScanResult, profile: Profile | None, excluded=frozenset()):
        self.profile = profile or Profile()
        model = result.app_model
        self.model = model
        self.controls = set(model.controls)
        self.detected = {c: sorted(v) for c, v in model.data_fields.items()}
        self.declared = set(self.profile.data_categories)
        self.categories = set(self.detected) | self.declared
        routes = sorted(result.routes, key=lambda r: (r.relpath, r.line, r.method, r.path))
        self.routes = routes
        self.login_routes = [r for r in routes if _LOGIN.search(r.path)]
        self.upload_routes = [
            r for r in routes if r.relpath in model.upload_files or "upload" in r.path.lower()
        ]
        self.admin_routes = [r for r in routes if "/admin" in r.path.lower()]
        self.state_routes = [r for r in routes if r.method.upper() in _STATE_CHANGING]
        self.url_params = sorted(model.url_params)
        self.outbound_http = any("outbound HTTP" in t or t == "aiohttp" for t in model.technologies)
        self.frameworks = sorted(model.technologies & _FRAMEWORKS)
        self.manifests = sorted(result.manifests)
        self.lockfiles = result.lockfiles
        self.sites = _finding_sites(result, excluded)

    def count(self, *types: str) -> dict[str, int]:
        return {t: len(self.sites[t]) for t in types if self.sites.get(t)}

    def band(self) -> int | None:
        eu = self.profile.expected_users
        return USER_BANDS.index(eu) if eu else None


def _finding_sites(result: ScanResult, excluded) -> dict[str, list[str]]:
    """Finding type -> locations, from the findings that remain after ignores and suppressions."""
    at = lambda f: f"{f.relpath}:{f.line}"  # noqa: E731
    pairs = [("hardcoded_secret", at(f)) for f in result.secret_findings]
    pairs += [("missing_function_level_authorization", f"{f.route.relpath}:{f.route.line}")
              for f in result.route_findings]  # fmt: skip
    pairs += [(f.category, at(f)) for f in result.sink_findings]
    pairs += [(f.vuln_type, at(f)) for f in result.taint_findings]
    pairs += [("idor", at(f)) for f in result.idor_findings]
    for group in (result.misconfig_findings, result.logging_findings, result.logic_findings):
        pairs += [(f.category, at(f)) for f in group]
    pairs += [("vulnerable_dependency", f.dependency.relpath) for f in result.dependency_findings]
    sites: dict[str, list[str]] = {}
    for ftype, where in sorted(pairs):
        if (ftype, where) not in excluded:
            sites.setdefault(ftype, []).append(where)
    return sites


# --------------------------------------------------------------------------- helpers


def _ev(location: str, detail: str) -> RecommendationEvidence:
    return RecommendationEvidence(location=location, detail=detail)


def _route_ev(routes) -> list[RecommendationEvidence]:
    return [_ev(f"{r.relpath}:{r.line}", f"route {r.method} {r.path}") for r in routes]


def _field_ev(sig: Signals, cats) -> list[RecommendationEvidence]:
    out = []
    for cat in sorted(cats):
        for relpath, line, label in sig.detected.get(cat, []):
            kind, _, name = label.partition(":")
            what = f"model field {name}" if kind == "field" else f"parameter {label}"
            out.append(_ev(f"{relpath}:{line}", f"{what} ({cat})"))
    return out


def _declared_ev(sig: Signals, cats=None) -> list[RecommendationEvidence]:
    chosen = sorted(sig.declared & set(cats) if cats is not None else sig.declared)
    return [_ev("profile", f"declared data category: {c}") for c in chosen]


def _origin(sig: Signals, cats) -> str:
    det, dec = sorted(set(cats) & set(sig.detected)), sorted(set(cats) & sig.declared)
    parts = ([f"detected in code ({', '.join(det)})"] if det else []) + (
        [f"declared in the profile ({', '.join(dec)})"] if dec else []
    )
    return " and ".join(parts)


def _basis(code: bool, profile: bool) -> str:
    return "code+profile" if code and profile else "profile" if profile else "code"


def _rec(rid, title, category, actions, evidence, refs, rationale, cannot, *, basis="code",
         priority="recommended", related=None) -> Recommendation:  # fmt: skip
    return Recommendation(
        id=rid, title=title, category=category, priority=priority, basis=basis,
        rationale=rationale, actions=actions, evidence=evidence[:_MAX_EVIDENCE],
        references=refs, cannot_verify=cannot, related_findings=related or {},
    )  # fmt: skip


def _users_at_least(sig: Signals, band: str) -> bool:
    got = sig.band()
    return got is not None and got >= USER_BANDS.index(band)


# --------------------------------------------------------------------------- rules


def hr_ratelimit_login(sig, p):
    if not sig.login_routes or "rate_limiting" in sig.controls:
        return None
    return _rec(
        "HR-RATELIMIT-LOGIN", "Throttle login and token endpoints", "authentication",
        ["Throttle attempts per account and per IP", "Add progressive delay or temporary lockout",
         "Return the same generic error for unknown user and wrong password"],
        _route_ev(sig.login_routes),
        ["OWASP ASVS 4.0 V2 Authentication", "OWASP Authentication Cheat Sheet"],
        "Login-like routes exist and no rate-limiting library or middleware was detected "
        "in imports or dependencies.",
        "A reverse proxy, API gateway, WAF or hand-written counter may already throttle these "
        "routes; none of these are visible in source.",
    )  # fmt: skip


def hr_ratelimit_api(sig, p):
    if "rate_limiting" in sig.controls:
        return None
    big = _users_at_least(sig, "10k-100k")
    if (p.exposure not in (None, "internet")) or (p.expected_users and not big):
        return None
    missing = [k for k in ("expected_users", "exposure") if not getattr(p, k)]
    if missing:
        return Need(missing)
    return _rec(
        "HR-RATELIMIT-API", "Limit request rates and quotas per client", "abuse_prevention",
        ["Apply per-client API rate limits and quotas", "Enforce limits at a gateway or WAF too"],
        [_ev("profile", f"declared exposure={p.exposure}, expected_users={p.expected_users}")],
        ["OWASP API Security Top 10 (2023) API4"],
        "The application is declared internet-facing for a large user base and no rate-limiting "
        "library or middleware was detected.",
        "Limits may be enforced by a CDN, gateway or WAF outside the repository.",
        basis="code+profile",
    )  # fmt: skip


def hr_mfa(sig, p):
    if not sig.login_routes or "mfa" in sig.controls:
        return None
    by_purpose = p.purpose in ("fintech", "healthcare", "government")
    if not sig.admin_routes and not by_purpose:
        return Need(["purpose"]) if not p.purpose else None
    ev = _route_ev(sig.admin_routes or sig.login_routes)
    if by_purpose:
        ev.append(_ev("profile", f"declared purpose: {p.purpose}"))
    return _rec(
        "HR-MFA", "Offer multi-factor authentication", "authentication",
        ["Require TOTP or WebAuthn for administrators first", "Offer MFA to ordinary users"],
        ev, ["OWASP ASVS 4.0 V2 Authentication"],
        "The application has login routes and a privileged surface, and no MFA library was "
        "detected in imports or dependencies.",
        "MFA may be delegated to an identity provider (SSO) that the code only redirects to.",
        basis=_basis(True, by_purpose),  # login routes are always code evidence
    )  # fmt: skip


def hr_password_hash(sig, p):
    if "credentials" not in sig.detected or "password_hashing" in sig.controls:
        return None
    return _rec(
        "HR-PASSWORD-HASH", "Store passwords with a slow password hash", "authentication",
        ["Use Argon2id or bcrypt with per-user salts", "Never store passwords reversibly"],
        _field_ev(sig, ["credentials"]), ["OWASP Password Storage Cheat Sheet"],
        "Credential-like fields were detected and no password-hashing library was detected "
        "in imports or dependencies.",
        "Hashing may live in a framework default (for example Django's) or an identity "
        "provider that is not import-detectable.",
        related=sig.count("weak_hash"),
    )  # fmt: skip


def hr_pii_encrypt(sig, p):
    cats = sig.categories & {"pii", "health", "government_id", "financial"}
    if not cats:
        return None
    det = cats & set(sig.detected)
    return _rec(
        "HR-PII-ENCRYPT", "Protect sensitive personal data at rest", "data_protection",
        ["Encrypt sensitive columns or volumes at rest", "Restrict who can read these fields",
         "Mask them in the UI and in logs"],
        _field_ev(sig, det) + _declared_ev(sig, cats),
        ["OWASP ASVS 4.0 V8 Data Protection", "OWASP ASVS 4.0 V6 Stored Cryptography"],
        f"Sensitive personal data is {_origin(sig, cats)}.",
        "Database, disk and backup encryption and access controls are configured outside source.",
        basis=_basis(bool(det), bool(sig.declared & cats)),
    )  # fmt: skip


def hr_pii_minimise(sig, p):
    if not sig.categories:
        return None
    det = set(sig.detected)
    return _rec(
        "HR-PII-MINIMISE", "Collect and keep only the data you need", "data_protection",
        ["Collect only what is needed", "Define a retention period and a deletion job",
         "Provide a way to export and delete a user's data"],
        _field_ev(sig, det) + _declared_ev(sig, sig.categories),
        ["OWASP ASVS 4.0 V8 Data Protection"],
        f"Personal or sensitive data is {_origin(sig, sig.categories)}.",
        "Retention schedules, deletion jobs and data-subject processes are operational "
        "practice, not source.",
        basis=_basis(bool(det), bool(sig.declared)), priority="consider",
    )  # fmt: skip


def hr_payment_scope(sig, p):
    has_ctl = "payments" in sig.controls
    if "payment" not in sig.categories and not has_ctl:
        return None
    det = "payment" in sig.detected
    ev = _field_ev(sig, ["payment"]) + _declared_ev(sig, ["payment"])
    if has_ctl and sig.model.control_files.get("payments"):
        ev.append(_ev(sig.model.control_files["payments"], "payment provider SDK imported"))
    return _rec(
        "HR-PAYMENT-SCOPE", "Keep card data out of your systems", "payments",
        ["Use the provider's hosted fields or tokenization", "Never store card number or CVV",
         "Verify payment webhooks by signature"],
        ev, ["PCI DSS"],
        "Payment data or a payment provider integration is present; keeping card data away "
        "from your servers reduces the scope of PCI DSS obligations.",
        "What the provider's client-side integration actually sends, and your PCI DSS "
        "scoping, cannot be established from source.",
        basis=_basis(det or has_ctl, "payment" in sig.declared),
    )  # fmt: skip


def hr_payment_server_price(sig, p):
    has_ctl = "payments" in sig.controls
    by_purpose = p.purpose in ("ecommerce", "fintech")
    if not has_ctl and not by_purpose:
        return Need(["purpose"]) if "payment" in sig.detected and not p.purpose else None
    ev = [_ev(sig.model.control_files["payments"], "payment provider SDK imported")] if (
        has_ctl and sig.model.control_files.get("payments")) else []  # fmt: skip
    if by_purpose:
        ev.append(_ev("profile", f"declared purpose: {p.purpose}"))
    return _rec(
        "HR-PAYMENT-SERVER-PRICE", "Decide amounts on the server", "payments",
        ["Compute prices and totals server-side", "Use idempotency keys on charge endpoints"],
        ev, ["OWASP ASVS 4.0 V11 Business Logic"],
        "The application takes payments or is declared to; amounts must never come from the "
        "client." + (" Existing client_trusted_value findings are reported separately."
                     if sig.count("client_trusted_value") else ""),
        "Whether amounts are recomputed server-side can only be confirmed by reading the "
        "charge path and, ideally, testing it.",
        basis=_basis(has_ctl, by_purpose), related=sig.count("client_trusted_value"),
    )  # fmt: skip


def hr_upload(sig, p):
    if not sig.upload_routes:
        return None
    return _rec(
        "HR-UPLOAD", "Constrain and isolate file uploads", "file_handling",
        ["Limit size and check type by content, not extension",
         "Store outside the web root under random names",
         "Scan for malware if users share files"],
        _route_ev(sig.upload_routes),
        ["OWASP File Upload Cheat Sheet", "OWASP ASVS 4.0 V12 Files and Resources"],
        "Routes that accept uploaded files were detected.",
        "Proxy body-size limits, storage permissions and any malware scanning sit outside "
        "the code.",
    )  # fmt: skip


def hr_headers(sig, p):
    if not sig.frameworks or not sig.routes or "security_headers" in sig.controls:
        return None
    return _rec(
        "HR-HEADERS", "Send security headers", "transport_headers",
        ["Set Content-Security-Policy and frame-ancestors", "Set HSTS and X-Content-Type-Options"],
        _route_ev(sig.routes[:1]), ["OWASP ASVS 4.0 V14 Configuration"],
        f"A web framework ({', '.join(sig.frameworks)}) serves routes and no security-headers "
        "library was detected.",
        "A reverse proxy, CDN or framework setting may already add these headers.",
        priority="consider",
    )  # fmt: skip


def hr_ssrf_egress(sig, p):
    if not sig.url_params or not sig.outbound_http:
        return None
    ev = [_ev(f"{r}:{n}", f"parameter {label}") for r, n, label in sig.url_params]
    return _rec(
        "HR-SSRF-EGRESS", "Restrict where the server may connect", "abuse_prevention",
        ["Allow-list outbound hosts", "Block private ranges and cloud metadata addresses",
         "Do not follow redirects to internal hosts"],
        ev, ["OWASP Server-Side Request Forgery Prevention Cheat Sheet"],
        "User-supplied URL parameters exist and an outbound HTTP client is in use.",
        "Network egress rules and metadata-service protections are infrastructure settings.",
        related=sig.count("ssrf"),
    )  # fmt: skip


def hr_audit_log(sig, p):
    sensitive = bool(sig.categories)
    if not sig.admin_routes and not (sig.state_routes and sensitive):
        return None
    ev = _route_ev(sig.admin_routes or sig.state_routes)
    return _rec(
        "HR-AUDIT-LOG", "Keep an audit trail of changes", "logging_monitoring",
        ["Record who changed what in an append-only log", "Alert on administrative actions",
         "Do not write sensitive values to the log"],
        ev, ["OWASP ASVS 4.0 V7 Error Handling and Logging",
             "OWASP Top 10 (2021) A09 Security Logging and Monitoring Failures"],
        "Administrative or state-changing routes exist" + (" alongside sensitive data." if (
            sensitive and not sig.admin_routes) else "."),
        "Audit logging may be done by a database trigger, gateway or SIEM outside the code.",
        priority="consider",
    )  # fmt: skip


def hr_monitoring(sig, p):
    if "error_monitoring" in sig.controls:
        return None
    if sig.band() is None:
        return Need(["expected_users"])
    if not _users_at_least(sig, "10k-100k"):
        return None
    return _rec(
        "HR-MONITORING", "Monitor errors and availability", "logging_monitoring",
        ["Add error tracking and uptime checks", "Route alerts to a named owner"],
        [_ev("profile", f"declared expected_users={p.expected_users}")],
        ["OWASP Top 10 (2021) A09 Security Logging and Monitoring Failures"],
        "A large user base is declared and no error-monitoring library was detected.",
        "Hosting-level monitoring, log pipelines and on-call rotas are outside the repository.",
        basis="code+profile", priority="consider",
    )  # fmt: skip


def hr_dependency_pipeline(sig, p):
    have = {m.rsplit("/", 1)[-1].lower() for m in sig.manifests}
    locks = {m.rsplit("/", 1)[-1].lower() for m in sig.lockfiles}
    js = "package.json" in have and not locks & {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
    py = bool(have & {"pyproject.toml", "pipfile"}) and not (
        locks & {"poetry.lock", "pipfile.lock", "uv.lock"}
        or any(x.startswith("requirements") for x in locks)
    )
    dep_findings = sig.count("vulnerable_dependency")
    if not (js or py) and not dep_findings:
        return None
    names = ({"package.json"} if js else set()) | ({"pyproject.toml", "pipfile"} if py else set())
    ev = [_ev(m, "manifest present, no lockfile found") for m in sig.manifests
          if m.rsplit("/", 1)[-1].lower() in names]  # fmt: skip
    ev += [
        _ev(w, "dependency with a known advisory")
        for w in sig.sites.get("vulnerable_dependency", [])
    ]
    return _rec(
        "HR-DEPENDENCY-PIPELINE", "Lock and keep dependencies current", "supply_chain",
        ["Commit lockfiles so versions are pinned", "Schedule automated dependency updates",
         "Run secureagent in CI (see action.yml)"],
        ev, ["OWASP Top 10 (2021) A06 Vulnerable and Outdated Components"],
        "A manifest without a lockfile was found, or dependency advisories were reported.",
        "A lockfile or update bot kept outside this directory is not visible here.",
        priority="consider", related=dep_findings,
    )  # fmt: skip


def hr_authz_review(sig, p):
    counts = sig.count(*_AUTHZ_TYPES)
    if not counts:
        return None
    if not p.expected_users:
        return Need(["expected_users"])
    ev = [_ev(w, f"open finding of type {t}") for t in _AUTHZ_TYPES for w in sig.sites.get(t, [])]
    return _rec(
        "HR-AUTHZ-REVIEW", "Centralise authorization decisions", "authentication",
        ["Use one central authorization policy, deny by default",
         "Check object ownership on every by-id access"],
        ev, ["OWASP ASVS 4.0 V4 Access Control", "OWASP API Security Top 10 (2023) API1"],
        f"{sum(counts.values())} authorization-related finding(s) are open and the application "
        f"is declared for {p.expected_users} users.",
        "Global middleware, a policy engine or database row-level security may already apply.",
        basis="code+profile", related=counts,
    )  # fmt: skip


def hr_compliance_note(sig, p):
    cats, regions = sig.categories, set(p.regions)
    if not cats:
        return None
    notes = []  # (display name, reference name)
    if "IN" in regions:
        notes.append(
            (
                "the Digital Personal Data Protection Act, 2023 (India)",
                "Digital Personal Data Protection Act, 2023",
            )
        )
    if "EU" in regions:
        notes.append(("GDPR", "GDPR"))
    if "US" in regions and "health" in cats:
        notes.append(("HIPAA (if the operator is a covered entity or business associate)", "HIPAA"))
    if "US" in regions and "children" in cats:
        notes.append(("COPPA", "COPPA"))
    if "payment" in cats:
        notes.append(("PCI DSS", "PCI DSS"))
    if not notes:
        return None if regions else Need(["regions"])
    det = cats & set(sig.detected)
    ev = [_ev("profile", f"declared regions: {', '.join(sorted(regions))}")] if regions else []
    ev += _field_ev(sig, det) + _declared_ev(sig, cats)
    return _rec(
        "HR-COMPLIANCE-NOTE", "Check which regulations may apply", "compliance_note",
        ["Ask whoever owns compliance which of these apply", "Record the decision and its owner"],
        ev, [ref for _, ref in notes],
        "; ".join(f"{name[0].upper() + name[1:]} may apply" for name, _ in notes)
        + f", given the declared regions and the data categories present; {_CONSULT}",
        "Whether any regime applies depends on the operator, users and processing, "
        "none of which source code shows.",
        basis=_basis(bool(det), bool(regions or sig.declared)), priority="consider",
    )  # fmt: skip


RULES = (
    hr_ratelimit_login, hr_ratelimit_api, hr_mfa, hr_password_hash, hr_pii_encrypt,
    hr_pii_minimise, hr_payment_scope, hr_payment_server_price, hr_upload, hr_headers,
    hr_ssrf_egress,
    hr_audit_log, hr_monitoring, hr_dependency_pipeline, hr_authz_review, hr_compliance_note,
)  # fmt: skip


def recommend(
    result: ScanResult, profile: Profile | None, excluded=frozenset()
) -> HardeningSummary:
    """Recommendations for a finished scan. ``excluded`` is a set of (finding type, endpoint)
    pairs (suppressed findings) that must not count in ``related_findings``."""
    sig = Signals(result, profile, excluded)
    big = (sig.band() or 0) >= USER_BANDS.index("100k-1m")
    recs: list[Recommendation] = []
    needs: list[dict] = []
    for rule in RULES:
        out = rule(sig, sig.profile)
        if isinstance(out, Need):
            needs.append({"id": rule.__name__.upper().replace("_", "-"), "missing": sorted(out)})
        elif out is not None:
            if big and out.id in _ESCALATE and out.priority == "consider":
                out = out.model_copy(update={
                    "priority": "recommended",
                    "rationale": out.rationale + " Raised to recommended because the declared "
                    "user base is 100k or more."})  # fmt: skip
            recs.append(out)
    recs.sort(key=lambda r: (r.priority != "recommended", r.category, r.id))
    needs.sort(key=lambda n: n["id"])
    return HardeningSummary(
        profile_declared=sig.profile.declared(),
        data_categories_detected=sorted(sig.detected),
        observed_controls=sorted(sig.controls),
        recommendations=recs,
        needs_profile=needs,
    )
