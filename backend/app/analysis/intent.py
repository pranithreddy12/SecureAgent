"""Developer intent spec: declared rules checked against the extracted application model.

A ``secureagent-intent.json`` file states what the code is *meant* to enforce; SecureAgent
reports where the source does not show it (ADR-010). Deterministic and read-only.

    {"rules": [
      {"id": "admin-needs-auth", "type": "require_auth", "paths": ["/admin/*"]},
      {"id": "orders-are-private", "type": "owner_scoped", "paths": ["/orders/*"]},
      {"id": "no-client-roles", "type": "never_from_client", "fields": ["tenant_id"]}
    ]}
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass

from app.analysis.access_control import IdorFinding
from app.analysis.business_logic import CATEGORY, LogicFinding
from app.analysis.routes import Route

DEFAULT_FILENAME = "secureagent-intent.json"
RULE_TYPES = {"require_auth", "owner_scoped", "never_from_client"}


class IntentError(ValueError):
    """The intent spec is unreadable or malformed."""


@dataclass(frozen=True)
class IntentRule:
    id: str
    type: str
    paths: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    description: str = ""


def load_intent(path: str) -> list[IntentRule]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise IntentError(f"cannot read intent spec {path}: {exc}") from exc
    except ValueError as exc:
        raise IntentError(f"intent spec {path} is not valid JSON: {exc}") from exc
    raw = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        raise IntentError(f"intent spec {path}: expected an object with a 'rules' list")
    rules: list[IntentRule] = []
    for i, item in enumerate(raw):
        rules.append(_parse_rule(path, i, item))
    return rules


def _parse_rule(path: str, i: int, item) -> IntentRule:
    where = f"intent spec {path}: rule #{i + 1}"
    if not isinstance(item, dict):
        raise IntentError(f"{where} must be an object")
    rtype = item.get("type")
    if rtype not in RULE_TYPES:
        raise IntentError(f"{where}: unknown type {rtype!r} (expected one of {sorted(RULE_TYPES)})")
    paths = _str_list(item.get("paths", []), where, "paths")
    fields = _str_list(item.get("fields", []), where, "fields")
    if rtype in {"require_auth", "owner_scoped"} and not paths:
        raise IntentError(f"{where}: '{rtype}' needs a non-empty 'paths' list")
    if rtype == "never_from_client" and not fields:
        raise IntentError(f"{where}: 'never_from_client' needs a non-empty 'fields' list")
    return IntentRule(
        id=str(item.get("id") or f"rule-{i + 1}"),
        type=rtype,
        paths=tuple(paths),
        fields=tuple(f.lower() for f in fields),
        description=str(item.get("description", "")),
    )


def _str_list(value, where: str, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise IntentError(f"{where}: '{key}' must be a list of strings")
    return value


def extra_fields(rules: list[IntentRule]) -> frozenset[str]:
    return frozenset(f for r in rules if r.type == "never_from_client" for f in r.fields)


def evaluate_intent(
    rules: list[IntentRule], routes: list[Route], idor: list[IdorFinding]
) -> list[LogicFinding]:
    """Check path-based rules. ``never_from_client`` is enforced by the detector itself
    (see ``extra_fields``) so its violations carry the real source line."""
    out: list[LogicFinding] = []
    idor_by_handler = {(f.relpath, f.handler): f for f in idor}
    for rule in rules:
        if rule.type == "never_from_client":
            continue
        for route in routes:
            if not any(fnmatch.fnmatch(route.path, pat) for pat in rule.paths):
                continue
            if rule.type == "require_auth" and not route.protected:
                out.append(
                    _violation(rule, route, "no authorization guard found on this endpoint", None)
                )
            elif rule.type == "owner_scoped":
                hit = idor_by_handler.get((route.relpath, route.handler))
                if hit:
                    out.append(
                        _violation(
                            rule,
                            route,
                            f"record looked up via {hit.lookup} without ownership scoping",
                            "CWE-639",
                        )
                    )
    return out


def _violation(rule: IntentRule, route: Route, why: str, cwe: str | None) -> LogicFinding:
    return LogicFinding(
        category="intent_violation",
        rule=f"{rule.id} [{rule.type}] — {route.method} {route.path}",
        severity=CATEGORY["intent_violation"][3],
        confidence=CATEGORY["intent_violation"][4],
        relpath=route.relpath,
        line=route.line,
        handler=route.handler or "",
        field=rule.id,
        evidence=why + (f" — {rule.description}" if rule.description else ""),
        cwe_override=cwe,
    )
