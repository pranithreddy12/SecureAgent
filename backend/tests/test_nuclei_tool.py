"""Nuclei wrapper: template selection and partial results when the scan cap is hit."""

from __future__ import annotations

import json
import subprocess

from app.schemas.pipeline import TargetScope
from app.tools import nuclei_tool
from app.tools.policy import RequestContext

CTX = RequestContext(
    authorized=True, scope=TargetScope(allowed_hosts=["example.com"]), demo=True
)  # demo: no DNS lookups
LINE = json.dumps(
    {
        "template-id": "git-config",
        "matched-at": "https://example.com/.git/config",
        "info": {"name": "Git Config Disclosure", "severity": "medium"},
    }
).encode()


def test_partial_output_survives_a_timeout(monkeypatch) -> None:
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        raise subprocess.TimeoutExpired(cmd, 300, output=LINE + b"\n")

    monkeypatch.setattr(nuclei_tool.subprocess, "run", fake_run)
    alerts = nuclei_tool.run_nuclei("https://example.com/", CTX)
    assert [a.name for a in alerts] == ["Git Config Disclosure"]
    assert seen["cmd"].count("-t") == 3 and "http/exposures" in seen["cmd"]
