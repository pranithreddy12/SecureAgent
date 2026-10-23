"""Nuclei subprocess wrapper: argv list only, intrusive/DoS tags excluded, output capped."""

from __future__ import annotations

import json
import shutil
import subprocess

from app.core.config import get_settings
from app.schemas.pipeline import RawToolAlert
from app.tools.policy import PolicyError, RequestContext, inspect_url

MAX_STDOUT = 2 * 1024 * 1024
EXCLUDED_TAGS = "dos,intrusive,fuzz,takeover,oast"


class NucleiUnavailable(Exception):
    pass


def run_nuclei(target_url: str, ctx: RequestContext) -> list[RawToolAlert]:
    inspect_url(target_url, ctx)
    settings = get_settings()
    binary = shutil.which(settings.nuclei_path) or settings.nuclei_path
    cmd = [
        binary,
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-nc",
        "-rl",
        str(max(1, int(settings.requests_per_second))),
        "-c",
        "5",
        "-timeout",
        str(min(settings.scan_timeout, 30)),
        "-exclude-tags",
        EXCLUDED_TAGS,
    ]
    try:
        proc = subprocess.run(  # noqa: S603 - argv list from settings + validated URL, never shell
            cmd,
            capture_output=True,
            timeout=min(settings.max_scan_duration, 300),
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise NucleiUnavailable("Nuclei binary is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise NucleiUnavailable("Nuclei timed out") from exc
    stdout = proc.stdout[:MAX_STDOUT]
    alerts: list[RawToolAlert] = []
    for line in stdout.splitlines()[:500]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        url = str(item.get("matched-at") or item.get("host") or target_url)
        try:
            inspect_url(url, ctx)
        except PolicyError:
            continue
        classification = info.get("classification") or {}
        cwes = classification.get("cwe-id") or []
        cve_ids = classification.get("cve-id") or info.get("cve-id") or []
        cvss = None
        metrics = classification.get("cvss-metrics")
        score = classification.get("cvss-score")
        if isinstance(score, (int, float)):
            cvss = {"score": float(score), "vector": metrics, "version": "3.1"}
        cve = None
        if isinstance(cve_ids, list) and cve_ids:
            cve = str(cve_ids[0])
        elif isinstance(cve_ids, str) and cve_ids.upper().startswith("CVE-"):
            cve = cve_ids
        alerts.append(
            RawToolAlert(
                source="nuclei",
                name=str(info.get("name") or item.get("template-id") or "Nuclei alert"),
                url=url,
                severity=str(info.get("severity") or "info").lower(),
                description=str(info.get("description") or "")[:2000],
                evidence=str(item.get("extracted-results") or item.get("matcher-name") or "")[:500],
                cwe=str(cwes[0]) if isinstance(cwes, list) and cwes else None,
                cve=cve,
                cvss=cvss,
                extra={"template": item.get("template-id")},
            )
        )
    return alerts
