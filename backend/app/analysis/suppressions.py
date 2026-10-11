"""Justified, expiring suppressions of individual findings (the feedback loop).

``secureagent-suppressions.json`` lives in the repository root and is meant to be code-reviewed:

    {"version": 1, "suppressions": [{
        "fingerprint": "3f9a1c0be2d4a7f1", "type": "sql_injection", "location": "db.py",
        "title": "Sql Injection (tainted input -> conn.execute)",
        "reason": "conn.execute(query, *args) is the DB wrapper; callers bind values as $n",
        "by": "pranith", "created": "2026-10-12", "expires": "2027-01-12", "count": 1 }]}

Rules that keep it honest:
- a reason of at least 10 characters is required (an unexplained suppression is just a hidden bug);
- ``expires`` is optional but recommended; an expired suppression stops applying and is reported;
- ``count`` is how many matching findings existed when it was written: a *new* identical finding in
  the same file is not silently hidden;
- suppressed findings are never deleted: they become ``false_positive`` with the reason attached.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import date

FILENAME = "secureagent-suppressions.json"
MIN_REASON = 10
_FP = re.compile(r"^[0-9a-f]{8,64}$")


class SuppressionError(ValueError):
    """The suppression file is unreadable or an entry is invalid."""


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    type: str
    location: str  # file only (line numbers move)
    title: str
    reason: str
    by: str
    created: str
    expires: str | None = None
    count: int = 1

    def expired(self, today: date) -> bool:
        return bool(self.expires) and date.fromisoformat(self.expires) < today  # type: ignore[arg-type]


def _parse(path: str, i: int, raw) -> Suppression:
    where = f"suppressions file {path}: entry #{i + 1}"
    if not isinstance(raw, dict):
        raise SuppressionError(f"{where} must be an object")
    fp = str(raw.get("fingerprint", "")).lower()
    if not _FP.match(fp):
        raise SuppressionError(f"{where}: 'fingerprint' must be 8-64 hex characters")
    reason = str(raw.get("reason", "")).strip()
    if len(reason) < MIN_REASON:
        raise SuppressionError(
            f"{where}: a 'reason' of at least {MIN_REASON} characters is required"
        )
    expires = raw.get("expires")
    if expires is not None:
        try:
            date.fromisoformat(str(expires))
        except ValueError:
            raise SuppressionError(f"{where}: 'expires' must be YYYY-MM-DD") from None
        expires = str(expires)
    count = raw.get("count", 1)
    if not isinstance(count, int) or count < 1:
        raise SuppressionError(f"{where}: 'count' must be a positive integer")
    return Suppression(
        fingerprint=fp,
        type=str(raw.get("type", "")),
        location=str(raw.get("location", "")),
        title=str(raw.get("title", "")),
        reason=reason,
        by=str(raw.get("by", "")) or "unknown",
        created=str(raw.get("created", "")),
        expires=expires,
        count=count,
    )


def load(path: str) -> list[Suppression]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise SuppressionError(f"cannot read suppressions file {path}: {exc}") from exc
    except ValueError as exc:
        raise SuppressionError(f"suppressions file {path} is not valid JSON: {exc}") from exc
    items = data.get("suppressions") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise SuppressionError(f"suppressions file {path}: expected an object with a list")
    return [_parse(path, i, raw) for i, raw in enumerate(items)]


def add(path: str, entry: Suppression) -> None:
    """Append an entry (creating the file), replacing an existing one for the same fingerprint."""
    try:
        existing = load(path)
    except SuppressionError as exc:
        if "cannot read" not in str(exc):
            raise
        existing = []
    merged = [s for s in existing if s.fingerprint != entry.fingerprint] + [entry]
    merged.sort(key=lambda s: (s.location, s.type, s.fingerprint))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(
            {"version": 1, "suppressions": [asdict(s) for s in merged]},
            fh,
            indent=2,
            ensure_ascii=False,
        )
        fh.write("\n")


def apply(findings, suppressions: list[Suppression], fingerprint_of, today: date | None = None):
    """Return ``(findings, applied, expired)``.

    Matching findings (same fingerprint, at most ``count`` of them, in file/line order) become
    ``false_positive`` with the justification as their reason.
    """
    from app.core.enums import FindingStatus

    today = today or date.today()
    active: dict[str, Suppression] = {}
    expired: list[Suppression] = []
    for s in suppressions:
        if s.expired(today):
            expired.append(s)
        else:
            active[s.fingerprint] = s
    remaining = {fp: s.count for fp, s in active.items()}
    out = []
    applied = 0
    for f in findings:
        fp = fingerprint_of(f)
        # accept a unique prefix (the CLI shows 8-char ids)
        key = fp if fp in active else next((a for a in active if fp.startswith(a)), None)
        if key and remaining.get(key, 0) > 0 and f.status is not FindingStatus.FALSE_POSITIVE:
            remaining[key] -= 1
            s = active[key]
            applied += 1
            out.append(
                f.model_copy(
                    update={
                        "status": FindingStatus.FALSE_POSITIVE,
                        "status_reason": (
                            f"Suppressed by {s.by} on {s.created or 'an earlier date'}: {s.reason}"
                            + (f" (expires {s.expires})" if s.expires else "")
                        ),
                    }
                )
            )
        else:
            out.append(f)
    return out, applied, expired
