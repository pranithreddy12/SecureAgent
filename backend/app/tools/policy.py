"""Defence-in-depth: every outbound request re-checks authorization, safety and scope."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import get_settings
from app.schemas.pipeline import TargetScope
from app.security.target_validation import InvalidTargetURL, TargetCheck, check_url, in_scope


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class RequestContext:
    authorized: bool
    scope: TargetScope
    demo: bool = False
    cancelled: bool = False


def inspect_url(url: str, ctx: RequestContext) -> TargetCheck:
    if ctx.cancelled:
        raise PolicyError("Audit was stopped")
    if not ctx.authorized:
        raise PolicyError("Target is not authorized for testing")
    if ctx.demo:
        # Demo adapters never open a socket; syntax/scope still apply.
        from urllib.parse import urlsplit

        from app.security.target_validation import normalize_url

        try:
            normalised = normalize_url(url)
        except InvalidTargetURL as exc:
            raise PolicyError(str(exc)) from exc
        if not in_scope(normalised, ctx.scope.model_dump()):
            raise PolicyError("URL is outside the authorized scope")
        host = urlsplit(normalised).hostname or ""
        return TargetCheck(True, normalised, host, "demo")
    settings = get_settings()
    try:
        check = check_url(
            url,
            allow_private=settings.allow_private_targets,
            allowlist=settings.target_allowlist,
        )
    except InvalidTargetURL as exc:
        raise PolicyError(str(exc)) from exc
    if not check.allowed:
        raise PolicyError(check.reason)
    if not in_scope(check.url, ctx.scope.model_dump()):
        raise PolicyError("URL is outside the authorized scope")
    return check
