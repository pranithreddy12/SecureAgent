"""OWASP ZAP REST client. Scope is pushed into the ZAP context; active scan uses LOW strength."""

from __future__ import annotations

import json
import time
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from app.core.config import get_settings
from app.schemas.pipeline import RawToolAlert, TargetScope
from app.tools.policy import PolicyError, RequestContext, inspect_url


class ZapUnavailable(Exception):
    pass


def _zap(path: str, params: dict[str, str] | None = None) -> dict:
    settings = get_settings()
    if not settings.zap_api_key:
        raise ZapUnavailable("ZAP API key is not configured")
    query = dict(params or {})
    query["apikey"] = settings.zap_api_key
    url = settings.zap_url.rstrip("/") + path + "?" + urlencode(query)
    req = Request(url, method="GET")  # noqa: S310 - ZAP URL comes from settings, not user input
    try:
        with urlopen(req, timeout=settings.scan_timeout) as resp:  # noqa: S310
            body = resp.read(1024 * 1024)
    except (URLError, TimeoutError, OSError) as exc:
        raise ZapUnavailable(str(exc)) from exc
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ZapUnavailable("ZAP returned non-JSON") from exc


def run_zap(target_url: str, ctx: RequestContext) -> list[RawToolAlert]:
    """Spider + passive scan + low-strength active scan. Returns *potential* alerts."""
    inspect_url(target_url, ctx)
    settings = get_settings()
    include = _include_regex(ctx.scope)
    try:
        _zap("/JSON/core/action/newSession/", {"name": "secureagent", "overwrite": "true"})
        ctx_id = _zap("/JSON/context/action/newContext/", {"contextName": "secureagent"}).get(
            "contextId", "1"
        )
        _zap(
            "/JSON/context/action/includeInContext/",
            {"contextName": "secureagent", "regex": include},
        )
        scan_id = _zap(
            "/JSON/spider/action/scan/",
            {"url": target_url, "contextName": "secureagent", "maxChildren": "20"},
        ).get("scan", "0")
        _wait(
            "/JSON/spider/view/status/",
            {"scanId": str(scan_id)},
            timeout=min(120, settings.max_scan_duration),
        )
        ascan = _zap(
            "/JSON/ascan/action/scan/",
            {
                "url": target_url,
                "contextId": str(ctx_id),
                "recurse": "true",
                "scanPolicyName": "",
            },
        ).get("scan", "0")
        # Best-effort: lower attack strength if the endpoint exists.
        try:
            _zap(
                "/JSON/ascan/action/setPolicyAttackStrength/",
                {"id": "0", "attackStrength": "LOW", "scanPolicyName": ""},
            )
        except ZapUnavailable:
            pass
        _wait(
            "/JSON/ascan/view/status/",
            {"scanId": str(ascan)},
            timeout=min(300, settings.max_scan_duration),
        )
        raw = _zap("/JSON/core/view/alerts/", {"baseurl": target_url, "start": "0", "count": "200"})
    except ZapUnavailable:
        raise
    alerts = raw.get("alerts") or []
    out: list[RawToolAlert] = []
    for item in alerts[:200]:
        url = str(item.get("url") or target_url)
        try:
            inspect_url(url, ctx)
        except PolicyError:
            continue
        cwe = item.get("cweid")
        cwe_s = f"CWE-{cwe}" if cwe and str(cwe) not in {"0", "None"} else None
        out.append(
            RawToolAlert(
                source="zap",
                name=str(item.get("alert") or item.get("name") or "ZAP alert"),
                url=url,
                parameter=item.get("param") or None,
                severity=str(item.get("risk") or "informational").lower(),
                description=str(item.get("description") or "")[:2000],
                evidence=str(item.get("evidence") or "")[:500],
                cwe=cwe_s,
                extra={"pluginId": item.get("pluginId")},
            )
        )
    return out


def _include_regex(scope: TargetScope) -> str:
    hosts = "|".join(_escape(h) for h in scope.allowed_hosts) or "localhost"
    return rf"https?://({hosts})/.*"


def _escape(host: str) -> str:
    return "".join("\\" + c if c in r".^$*+?{}[]|()\\" else c for c in host)


def _wait(path: str, params: dict[str, str], *, timeout: int) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = _zap(path, params)
        status = str(data.get("status") or data.get("value") or "0")
        if status.isdigit() and int(status) >= 100:
            return
        time.sleep(2)
    raise ZapUnavailable(f"ZAP stage timed out ({path})")
