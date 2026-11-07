"""Cross-account object access check (BOLA / IDOR) against an authorized live target.

The owner supplies two test accounts of *their own* application (A and B) as request headers, and
URLs of objects that belong to A. For each URL, read-only GET requests are made as A, as nobody,
and as B:

* A must be able to read it (otherwise it is not A's object -- skipped);
* if an anonymous request returns the same content, the object is public -- not a finding;
* if B receives A's content, object-level authorization is missing -> **confirmed** finding;
* 401/403/404 for B means authorization is enforced.

Every request goes through ``app.tools.http.fetch`` (GET/HEAD only, scope + SSRF policy re-checked
on every hop, size-capped). Credentials are held in memory for the run only, never persisted, and
never written into evidence (bodies are compared by hash and similarity, not quoted).
"""

from __future__ import annotations

import difflib
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.enums import Severity
from app.schemas.pipeline import SuspectedFinding, ValidationResult
from app.tools.http import HttpResponse, fetch
from app.tools.policy import PolicyError, RequestContext

MAX_URLS = 50
MAX_HEADER_VALUE = 4096
SIMILAR = 0.9  # body similarity at or above this counts as "the same object"
_ALLOWED_HEADER = re.compile(r"^(authorization|cookie|x-[a-z0-9-]{1,40})$", re.IGNORECASE)

Fetcher = Callable[[str, RequestContext, dict[str, str]], HttpResponse]


class AccessCheckError(ValueError):
    pass


@dataclass(frozen=True)
class AccessCheckConfig:
    user_a: dict[str, str]
    user_b: dict[str, str]
    urls: list[str]


@dataclass
class AccessOutcome:
    url: str
    verdict: str  # exposed | enforced | public | not_owned | inconclusive | blocked
    a_status: int | None = None
    b_status: int | None = None
    anon_status: int | None = None
    similarity: float | None = None
    note: str = ""
    evidence: dict = field(default_factory=dict)


def _headers(raw, who: str) -> dict[str, str]:
    if not isinstance(raw, dict) or not raw:
        raise AccessCheckError(f"{who}: give at least one header (e.g. Cookie or Authorization).")
    out: dict[str, str] = {}
    for name, value in raw.items():
        name, value = str(name).strip(), str(value)
        if not _ALLOWED_HEADER.match(name):
            raise AccessCheckError(
                f"{who}: header '{name}' is not allowed (use Authorization, Cookie or X-*)."
            )
        if "\r" in value or "\n" in value or len(value) > MAX_HEADER_VALUE:
            raise AccessCheckError(f"{who}: header '{name}' has an invalid value.")
        out[name] = value
    return out


def parse_config(raw: dict | None) -> AccessCheckConfig | None:
    """Validate the owner's input. ``None``/empty means "no access check requested"."""
    if not raw:
        return None
    urls = [str(u).strip() for u in raw.get("urls") or [] if str(u).strip()]
    if not urls:
        raise AccessCheckError("List at least one URL of an object owned by account A.")
    if len(urls) > MAX_URLS:
        raise AccessCheckError(f"At most {MAX_URLS} URLs per audit.")
    a = _headers(raw.get("user_a"), "Account A")
    b = _headers(raw.get("user_b"), "Account B")
    if a == b:
        raise AccessCheckError("Accounts A and B must use different credentials.")
    return AccessCheckConfig(a, b, urls)


def _default_fetch(url: str, ctx: RequestContext, headers: dict[str, str]) -> HttpResponse:
    return fetch(url, ctx, extra_headers=headers)


def _similarity(a: bytes, b: bytes) -> float:
    if a == b:
        return 1.0
    sa, sb = a[:8192].decode("utf-8", "replace"), b[:8192].decode("utf-8", "replace")
    return difflib.SequenceMatcher(None, sa, sb, autojunk=False).ratio()


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16]


def check_object(
    url: str,
    cfg: AccessCheckConfig,
    ctx: RequestContext,
    fetcher: Fetcher = _default_fetch,
    pause: Callable[[], None] = lambda: None,
) -> AccessOutcome:
    try:
        a = fetcher(url, ctx, cfg.user_a)
        if not 200 <= a.status < 300 or len(a.body.strip()) < 2:
            return AccessOutcome(url, "not_owned", a.status, note="Account A cannot read this URL.")
        pause()
        anon = fetcher(url, ctx, {})
        pause()
        b = fetcher(url, ctx, cfg.user_b)
    except PolicyError as exc:
        return AccessOutcome(url, "blocked", note=f"Request blocked by policy: {exc}")

    anon_sim = _similarity(a.body, anon.body) if 200 <= anon.status < 300 else 0.0
    b_sim = _similarity(a.body, b.body) if 200 <= b.status < 300 else 0.0
    evidence = {
        "a": {"status": a.status, "bytes": len(a.body), "sha256": _digest(a.body)},
        "anonymous": {"status": anon.status, "bytes": len(anon.body), "sha256": _digest(anon.body)},
        "b": {"status": b.status, "bytes": len(b.body), "sha256": _digest(b.body)},
        "b_similarity_to_a": round(b_sim, 3),
    }
    out = AccessOutcome(url, "", a.status, b.status, anon.status, round(b_sim, 3), "", evidence)
    if anon_sim >= SIMILAR:
        out.verdict, out.note = "public", "Anonymous requests receive the same content."
    elif b_sim >= SIMILAR:
        out.verdict, out.note = "exposed", "Account B received account A's object."
    elif b.status in {401, 403, 404}:
        out.verdict, out.note = "enforced", f"Account B was refused ({b.status})."
    else:
        out.verdict = "inconclusive"
        out.note = f"Account B got {b.status} with different content (similarity {b_sim:.0%})."
    return out


def to_findings(outcomes: list[AccessOutcome]) -> tuple[list[dict], list[dict]]:
    """(suspected findings, validation results) as JSON dicts for the pipeline state."""
    findings: list[dict] = []
    results: list[dict] = []
    for i, o in enumerate(o for o in outcomes if o.verdict == "exposed"):
        fid = f"access-check-{i + 1}"
        findings.append(
            SuspectedFinding(
                id=fid,
                title="Broken object level authorization (cross-account read)",
                type="bola",
                endpoint=o.url,
                severity=Severity.HIGH,
                confidence=0.9,
                description=(
                    "A second, unrelated account could read an object that belongs to the first "
                    "account. The application does not check that the requester owns the object."
                ),
                evidence=(
                    f"GET as A -> {o.a_status}; anonymous -> {o.anon_status}; as B -> "
                    f"{o.b_status} with {o.similarity:.0%} identical content (bodies compared by "
                    "hash/similarity, not stored)."
                ),
                owasp_category="API1:2023 Broken Object Level Authorization",
                cwe="CWE-639",
                sources=["live:access-check"],
                remediation=(
                    "Load the object scoped to the authenticated user or tenant (e.g. "
                    "WHERE id = :id AND owner_id = :current_user) and return 404 otherwise."
                ),
            ).model_dump(mode="json")
        )
        results.append(
            ValidationResult(
                finding_id=fid,
                validated=True,
                confidence=0.9,
                evidence=o.note,
                validation_method="two_account_differential_get",
                risk_notes="Read-only GET requests with the owner's own test accounts.",
            ).model_dump(mode="json")
        )
    return findings, results


def summarize(outcomes: list[AccessOutcome]) -> dict:
    counts: dict[str, int] = {}
    for o in outcomes:
        counts[o.verdict] = counts.get(o.verdict, 0) + 1
    return {
        "checked": len(outcomes),
        "verdicts": counts,
        "results": [
            {"url": o.url, "verdict": o.verdict, "note": o.note, **o.evidence} for o in outcomes
        ],
    }
