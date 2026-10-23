"""Bounded, scope-checked HTTP GET used by recon and safe validation.

Redirects are followed manually so every hop is re-validated (DNS-rebinding /
redirect-to-internal). Responses are size-capped. This client never sends
attacker-controlled payloads.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from app.core.config import get_settings
from app.tools.policy import PolicyError, RequestContext, inspect_url

MAX_BODY = 512 * 1024
MAX_REDIRECTS = 5
_SAFE_METHODS = frozenset({"GET", "HEAD"})


@dataclass
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


def fetch(
    url: str,
    ctx: RequestContext,
    *,
    method: str = "GET",
    extra_headers: dict[str, str] | None = None,
) -> HttpResponse:
    if method.upper() not in _SAFE_METHODS:
        raise PolicyError("Only GET and HEAD are permitted")
    settings = get_settings()
    current = inspect_url(url, ctx).url
    for _ in range(MAX_REDIRECTS + 1):
        req = Request(current, method=method.upper())  # noqa: S310 - scheme checked by inspect_url
        req.add_header("User-Agent", "SecureAgent/0.1 (authorized security audit)")
        for k, v in (extra_headers or {}).items():
            req.add_header(k, v)
        try:
            with urlopen(req, timeout=settings.scan_timeout) as resp:  # noqa: S310
                raw = resp.read(MAX_BODY + 1)
                final = inspect_url(resp.geturl(), ctx).url
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if len(raw) > MAX_BODY:
                    raw = raw[:MAX_BODY]
                return HttpResponse(final, getattr(resp, "status", 200), headers, raw)
        except HTTPError as exc:
            location = exc.headers.get("Location") if exc.headers else None
            if exc.code in {301, 302, 303, 307, 308} and location:
                nxt = urljoin(current, location)
                current = inspect_url(nxt, ctx).url
                continue
            body = exc.read(MAX_BODY) if exc.fp else b""
            headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
            return HttpResponse(current, exc.code, headers, body)
        except (URLError, TimeoutError, OSError) as exc:
            raise PolicyError(f"Request failed: {exc}") from exc
    raise PolicyError("Too many redirects")


def rate_sleep(last: float | None) -> float:
    rps = get_settings().requests_per_second
    gap = 1.0 / rps if rps else 0.2
    now = time.monotonic()
    if last is not None and now - last < gap:
        time.sleep(gap - (now - last))
    return time.monotonic()


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.forms: list[tuple[str, str, list[str]]] = []
        self._form: tuple[str, str, list[str]] | None = None
        self.scripts: list[str] = []
        self.generator: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and ad.get("href"):
            self.hrefs.append(ad["href"])
        elif tag == "form":
            self._form = (ad.get("action", ""), ad.get("method", "GET") or "GET", [])
        elif tag == "input" and self._form is not None and ad.get("name"):
            self._form[2].append(ad["name"])
        elif tag == "script" and ad.get("src"):
            self.scripts.append(ad["src"])
        elif tag == "meta" and ad.get("name", "").lower() == "generator":
            self.generator = ad.get("content") or None

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_html(body: bytes) -> _LinkParser:
    parser = _LinkParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001 - malformed HTML is not fatal
        pass
    return parser
