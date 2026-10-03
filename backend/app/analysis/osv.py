"""Query the OSV database (osv.dev) for known vulnerabilities in declared packages.

OSV is a free, public vulnerability database (no API key). This client only *reads*
advisory data for packages the project already declares — it sends package names and
versions, never source code or secrets. The HTTP layer is injectable so the mapping
logic is unit-tested without network access.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from app.analysis.dependencies import Dependency

QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/"
MAX_QUERIES = 2000
MAX_DETAIL_FETCHES = 150

# fetch(url, payload) -> response bytes. payload is None for GET.
Fetch = Callable[[str, bytes | None], bytes]


class OsvError(RuntimeError):
    pass


@dataclass(frozen=True)
class Vuln:
    id: str
    severity: str  # critical|high|medium|low|unknown
    summary: str
    url: str

    @property
    def cve(self) -> str | None:
        return self.id if self.id.startswith("CVE-") else None


def _default_fetch(url: str, payload: bytes | None) -> bytes:
    req = urllib.request.Request(  # noqa: S310 - fixed https osv.dev host, not user input
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "SecureAgent/0.1"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        return resp.read()


class OsvClient:
    def __init__(self, fetch: Fetch | None = None) -> None:
        self._fetch = fetch or _default_fetch

    def query(self, deps: list[Dependency]) -> dict[tuple[str, str, str], list[Vuln]]:
        """Return {dep.key: [Vuln, ...]} for packages with known advisories."""
        queryable = [d for d in deps if d.version][:MAX_QUERIES]
        if not queryable:
            return {}

        payload = json.dumps(
            {
                "queries": [
                    {"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version}
                    for d in queryable
                ]
            }
        ).encode()
        try:
            raw = self._fetch(QUERYBATCH_URL, payload)
            results = json.loads(raw).get("results", [])
        except (OSError, ValueError) as exc:
            raise OsvError(f"OSV query failed: {exc}") from exc

        # Collect unique vuln ids, then fetch details (bounded) for severity/summary.
        id_by_dep: dict[tuple[str, str, str], list[str]] = {}
        all_ids: list[str] = []
        for dep, res in zip(queryable, results, strict=False):
            ids = [v["id"] for v in (res or {}).get("vulns", []) if "id" in v]
            if ids:
                id_by_dep[dep.key] = ids
                all_ids.extend(ids)

        details = self._fetch_details(dict.fromkeys(all_ids))
        return {key: [details[i] for i in ids if i in details] for key, ids in id_by_dep.items()}

    def _fetch_details(self, ids) -> dict[str, Vuln]:
        out: dict[str, Vuln] = {}
        for vid in list(ids)[:MAX_DETAIL_FETCHES]:
            try:
                data = json.loads(self._fetch(VULN_URL + vid, None))
            except (OSError, ValueError):
                out[vid] = Vuln(vid, "unknown", "", f"https://osv.dev/vulnerability/{vid}")
                continue
            out[vid] = Vuln(
                id=vid,
                severity=_severity_of(data),
                summary=(data.get("summary") or "").strip()[:200],
                url=f"https://osv.dev/vulnerability/{vid}",
            )
        return out


def _severity_of(data: dict) -> str:
    spec = (data.get("database_specific") or {}).get("severity")
    if isinstance(spec, str) and spec.lower() in {"critical", "high", "medium", "moderate", "low"}:
        return "medium" if spec.lower() == "moderate" else spec.lower()
    # Fall back to a CVSS vector's base score if present.
    for sev in data.get("severity", []):
        score = str(sev.get("score", ""))
        band = _cvss_band(score)
        if band:
            return band
    return "unknown"


def _cvss_band(vector_or_score: str) -> str | None:
    # Accept a bare base score ("9.8") if present; CVSS vectors without a score are skipped.
    try:
        score = float(vector_or_score)
    except ValueError:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
