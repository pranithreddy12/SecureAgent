"""Opt-in live check of hardcoded secrets: is the credential still accepted by its provider?

Off unless the user passes ``--verify-secrets``, because it sends the secret to the provider that
issued it (and only to that provider, over https, to a read-only identity endpoint). That turns
"matches a key pattern" into one of:

* ``live``    -- the provider accepted it: a working credential is exposed (status confirmed);
* ``revoked`` -- the provider rejected it (expired/revoked/test placeholder);
* ``unknown`` -- no verifier for this kind of key, or the provider could not be reached.

Each call is a harmless "who am I" read; nothing is created, changed or listed beyond identity.
AWS keys are not verified (signing needs the secret key, which is usually not adjacent).
"""

from __future__ import annotations

import base64
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from app.analysis.secrets import PROVIDER_RULES, SecretFinding, _fingerprint

# fetch(url, method, headers, body) -> HTTP status, response body
Fetch = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


def _default_fetch(url: str, method: str, headers: dict[str, str], body: bytes | None):
    req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 - fixed https hosts
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def _github(token: str, fetch: Fetch) -> str:
    status, _ = fetch(
        "https://api.github.com/user",
        "GET",
        {"Authorization": f"Bearer {token}", "User-Agent": "SecureAgent"},
        None,
    )
    return "live" if status == 200 else "revoked" if status == 401 else "unknown"


def _slack(token: str, fetch: Fetch) -> str:
    status, body = fetch(
        "https://slack.com/api/auth.test", "POST", {"Authorization": f"Bearer {token}"}, b""
    )
    if status != 200:
        return "unknown"
    return "live" if b'"ok":true' in body.replace(b" ", b"") else "revoked"


def _stripe(token: str, fetch: Fetch) -> str:
    auth = base64.b64encode(f"{token}:".encode()).decode()
    status, _ = fetch(
        "https://api.stripe.com/v1/balance", "GET", {"Authorization": f"Basic {auth}"}, None
    )
    return "live" if status == 200 else "revoked" if status == 401 else "unknown"


VERIFIERS: dict[str, Callable[[str, Fetch], str]] = {
    "GitHub token": _github,
    "Slack token": _slack,
    "Stripe secret key": _stripe,
}


def verify_secrets(
    root: str, findings: list[SecretFinding], fetch: Fetch | None = None
) -> list[SecretFinding]:
    """Return ``findings`` with ``liveness`` set where a verifier exists. The raw value is re-read
    from the file (findings only hold a redacted copy) and matched by fingerprint."""
    fetch = fetch or _default_fetch
    rules = {r.name: r for r in PROVIDER_RULES if r.name in VERIFIERS}
    cache: dict[str, str] = {}
    out: list[SecretFinding] = []
    base = Path(root).resolve()
    for f in findings:
        rule = rules.get(f.rule)
        if rule is None:
            out.append(f)
            continue
        verdict = cache.get(f.fingerprint)
        if verdict is None:
            verdict = "unknown"
            try:
                line = (base / f.relpath).read_text(encoding="utf-8").splitlines()[f.line - 1]
            except (OSError, UnicodeDecodeError, IndexError):
                line = ""
            for m in rule.pattern.finditer(line):
                if _fingerprint(m.group(0)) == f.fingerprint:
                    try:
                        verdict = VERIFIERS[f.rule](m.group(0), fetch)
                    except OSError:
                        verdict = "unknown"
                    break
            cache[f.fingerprint] = verdict
        out.append(replace(f, liveness=verdict))
    return out
