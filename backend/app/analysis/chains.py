"""Attack chains: findings that are worse together than apart (ADR-012).

A flat findings list hides how weaknesses combine. These rules link findings that are related by
*structure* (the same route, or the same application) into a short narrative with the one fix
that removes the most risk. Rules are deterministic and conservative: a chain is reported only
when its members are actually present, and every chain says what it assumes. Chains are an
interpretation of findings, not findings themselves -- they never change a finding's status and
are excluded from baselines and gating.
"""

from __future__ import annotations

import re
from collections import defaultdict

from app.analysis.routes import Route
from app.core.enums import FindingStatus, Severity
from app.schemas.report import AttackChain, ChainMember, ReportFinding, type_label

_LOCATION = re.compile(r"^(?P<file>.*):(?P<line>\d+)$")
_ORDER = [Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Sinks an anonymous caller can drive if the route has no guard.
EXECUTION_TYPES = {
    "sql_injection",
    "command_injection",
    "code_injection",
    "ssrf",
    "path_traversal",
    "insecure_deserialization",
}
ESCALATION_TYPES = {"mass_assignment", "client_trusted_privilege"}
UNGUARDED_TYPES = {
    "missing_function_level_authorization",
    "inconsistent_authorization",
}


def _worst(severities: list[Severity]) -> Severity:
    return max(severities, key=_ORDER.index)


def _where(f: ReportFinding) -> tuple[str, int] | None:
    m = _LOCATION.match(f.endpoint or "")
    return (m["file"], int(m["line"])) if m else None


def _member(role: str, f: ReportFinding) -> ChainMember:
    return ChainMember(
        role=role, title=f.title, type=f.type, location=f.endpoint, severity=f.severity
    )


class _RouteIndex:
    """Maps (file, line) to the route whose handler contains it (the next route def bounds it)."""

    def __init__(self, routes: list[Route]) -> None:
        by_file: dict[str, list[Route]] = defaultdict(list)
        for r in routes:
            by_file[r.relpath].append(r)
        self._by_file = {k: sorted(v, key=lambda r: r.line) for k, v in by_file.items()}

    def containing(self, file: str, line: int) -> Route | None:
        found: Route | None = None
        for r in self._by_file.get(file, []):
            if r.line <= line:
                found = r
            else:
                break
        return found


def find_chains(findings: list[ReportFinding], routes: list[Route]) -> list[AttackChain]:
    findings = [f for f in findings if f.status is not FindingStatus.INFORMATIONAL]
    index = _RouteIndex(routes)
    chains: list[AttackChain] = []
    seen: set[tuple[str, ...]] = set()

    def add(chain: AttackChain, key: tuple[str, ...]) -> None:
        if key not in seen:
            seen.add(key)
            chains.append(chain)

    # Findings that point at an unguarded route, keyed by the route they sit on.
    unguarded_by_route: dict[tuple[str, int], ReportFinding] = {}
    for f in findings:
        loc = _where(f)
        if loc and (
            f.type in UNGUARDED_TYPES
            or (f.type == "intent_violation" and "[require_auth]" in f.title)
        ):
            unguarded_by_route[loc] = f

    for f in findings:
        loc = _where(f)
        if loc is None or f.type not in EXECUTION_TYPES | ESCALATION_TYPES | {"idor"}:
            continue
        route = index.containing(*loc)
        if route is None or route.protected:
            continue
        entry = unguarded_by_route.get((route.relpath, route.line))
        entry_member = (
            _member("entry: no authentication", entry)
            if entry
            else ChainMember(
                role="entry: no authentication",
                title=f"Endpoint without visible authorization: {route.method} {route.path}",
                type="missing_function_level_authorization",
                location=f"{route.relpath}:{route.line}",
                severity=Severity.MEDIUM,
            )
        )
        endpoint = f"{route.method} {route.path}"
        if f.type in EXECUTION_TYPES:
            title = f"{type_label(f.type)} reachable without authentication: {endpoint}"
            impact = "an anonymous caller can reach the vulnerable sink directly"
            step = f"Send crafted input to {endpoint} (no credentials required)."
            role = "payload: attacker input reaches a dangerous sink"
        elif f.type == "idor":
            title = f"Unauthenticated access to other users' records via {endpoint}"
            impact = "an anonymous caller can enumerate record ids"
            step = f"Request {endpoint} with different record ids (no credentials required)."
            role = "amplifier: no ownership check on the lookup"
        else:
            title = f"Anonymous privilege escalation via {endpoint}"
            impact = "an anonymous caller can set privileged fields"
            step = f"Submit privileged fields (role/is_admin/...) to {endpoint}."
            role = "amplifier: privileged fields accepted from the client"
        # No escalation: a chain explains how findings combine; it never ranks above its worst
        # member (reports must not inflate severity). The exposure is stated in the narrative.
        severity = _worst([f.severity, entry_member.severity])
        add(
            AttackChain(
                id=f"chain-{len(chains) + 1}",
                title=title,
                severity=severity,
                summary=(
                    f"{endpoint} has no visible authorization and its handler contains a "
                    f"{type_label(f.type).lower() if f.type != 'ssrf' else 'SSRF'} weakness "
                    f"({f.endpoint}): {impact}."
                ),
                steps=[
                    step,
                    f"The handler processes it: {type_label(f.type)} at {f.endpoint}.",
                    "Impact: " + (f.impact or "see the finding").rstrip("."),
                ],
                members=[entry_member, _member(role, f)],
                fix_first=(
                    f"Fix the weakness at {f.endpoint} first: it removes the risk for every "
                    "caller. Adding authentication alone would still leave signed-in users "
                    "able to exploit it."
                    if f.type in EXECUTION_TYPES
                    else f"Add authentication/authorization to {endpoint} first, then "
                    f"fix the weakness at {f.endpoint}."
                ),
                assumptions=[
                    "No global middleware or gateway enforces authentication for this route "
                    "(static analysis cannot see one).",
                ],
            ),
            (entry_member.location, f.type, f.endpoint),
        )

    # Cross-site request abuse: credentialed wildcard CORS + CSRF protection off.
    cors = next((f for f in findings if f.type == "permissive_cors"), None)
    csrf = next((f for f in findings if f.type == "csrf_disabled"), None)
    if cors and csrf:
        add(
            AttackChain(
                id=f"chain-{len(chains) + 1}",
                title="Cross-site request abuse of signed-in users",
                severity=_worst([cors.severity, csrf.severity]),
                summary=(
                    "Cross-origin requests are allowed with credentials and CSRF protection is "
                    "off, so a malicious page can act as a signed-in user."
                ),
                steps=[
                    "Lure a signed-in user to an attacker-controlled page.",
                    "The page issues state-changing requests; CORS permits the credentialed call.",
                    "CSRF protection is disabled, so the server accepts them as the user.",
                ],
                members=[
                    _member("enabler: cross-origin access with credentials", cors),
                    _member("enabler: no CSRF protection", csrf),
                ],
                fix_first=(
                    f"Restrict CORS origins ({cors.endpoint}); it also stops the attacker "
                    "reading responses. Re-enable CSRF protection as defence in depth."
                ),
                assumptions=["Authentication relies on cookies sent automatically by the browser."],
            ),
            (cors.endpoint, csrf.endpoint),
        )

    rank = {s: i for i, s in enumerate(reversed(_ORDER))}
    chains.sort(key=lambda c: (rank[c.severity], c.title))
    for i, c in enumerate(chains, 1):
        c.id = f"chain-{i}"
    return chains
