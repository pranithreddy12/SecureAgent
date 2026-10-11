"""Authorization matrix: route x guard grid, and the routes that break their siblings' pattern.

Routes are grouped by resource (first path segment). When most routes of a resource are guarded
and one is not, the odd one out is a strong review signal: the developer clearly meant the
resource to be protected, so the unguarded sibling is more likely an omission than a decision
(ADR-010). Static and heuristic -- a global middleware or per-route policy the extractor cannot
see can still explain it, so findings stay "suspicious".
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.analysis.business_logic import LogicFinding
from app.analysis.routes import PRIVILEGED_PATH, STATE_CHANGING, Route

MIN_GROUP = 3  # a pattern needs at least this many routes to be a pattern
GUARDED_SHARE = 0.6  # at least this share of the group must be guarded
# Resources that are public by design; never treated as an authorization pattern.
PUBLIC_RESOURCES = re.compile(
    r"(?i)^(login|logout|signin|signup|register|auth|health|healthz|status|ping|static|"
    r"public|docs|openapi\.json|favicon\.ico|robots\.txt|webhooks?|callback|oauth|token)$"
)


@dataclass(frozen=True)
class MatrixGroup:
    resource: str
    routes: tuple[Route, ...]

    @property
    def guarded(self) -> int:
        return sum(1 for r in self.routes if r.protected)


def resource_of(path: str) -> str:
    for seg in path.split("/"):
        seg = seg.strip()
        if seg and not seg.startswith(("<", "{", ":", "(")):
            return seg.lower()
    return "/"


def build_matrix(routes: list[Route]) -> list[MatrixGroup]:
    groups: dict[str, list[Route]] = {}
    for r in routes:
        groups.setdefault(resource_of(r.path), []).append(r)
    return [
        MatrixGroup(resource, tuple(sorted(rs, key=lambda r: (r.path, r.method))))
        for resource, rs in sorted(groups.items())
    ]


_PATH_PARAM = re.compile(r"<[^>]+>|\{[^}]+\}|/:[A-Za-z_]")


def _worth_flagging(route: Route) -> bool:
    """An unguarded *collection listing* (GET /items) is very often public by design (a catalogue,
    a status page). Flag unguarded state changes, object-level access (a path parameter), and
    paths that look privileged; do not flag a plain public listing among guarded siblings."""
    if route.method in STATE_CHANGING:
        return True
    return bool(_PATH_PARAM.search(route.path) or PRIVILEGED_PATH.search(route.path))


def authz_outliers(routes: list[Route]) -> list[LogicFinding]:
    out: list[LogicFinding] = []
    for g in build_matrix(routes):
        if PUBLIC_RESOURCES.match(g.resource) or len(g.routes) < MIN_GROUP:
            continue
        share = g.guarded / len(g.routes)
        if share < GUARDED_SHARE or g.guarded == len(g.routes):
            continue
        guards = sorted({r.guard for r in g.routes if r.protected and r.guard})
        for r in g.routes:
            if r.protected or not _worth_flagging(r):
                continue
            out.append(
                LogicFinding(
                    category="inconsistent_authorization",
                    rule=(
                        f"{r.method} {r.path} is unguarded; {g.guarded} of {len(g.routes)} "
                        f"'/{g.resource}' routes are guarded"
                    ),
                    severity="high" if r.method in {"POST", "PUT", "PATCH", "DELETE"} else "medium",
                    confidence=0.6,
                    relpath=r.relpath,
                    line=r.line,
                    handler=r.handler or "",
                    field=g.resource,
                    evidence=(
                        f"sibling routes use {', '.join(guards) or 'a guard'}; "
                        f"this one has none ({r.method} {r.path})"
                    ),
                )
            )
    return out
