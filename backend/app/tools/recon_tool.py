"""Same-scope crawler: pages, forms, headers, well-known API description paths."""

from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlsplit

from app.core.config import get_settings
from app.schemas.pipeline import ReconEndpoint, ReconForm, ReconResult
from app.tools.http import fetch, parse_html, rate_sleep
from app.tools.policy import PolicyError, RequestContext, inspect_url

INTERESTING = (
    "/robots.txt",
    "/sitemap.xml",
    "/openapi.json",
    "/swagger.json",
    "/.well-known/security.txt",
)
API_HINTS = ("/openapi.json", "/swagger.json", "/api", "/graphql")


def _tech_from_headers(headers: dict[str, str]) -> list[str]:
    techs: list[str] = []
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if headers.get(key):
            techs.append(f"{key}: {headers[key][:80]}")
    return techs


def crawl(start_url: str, ctx: RequestContext) -> ReconResult:
    settings = get_settings()
    start = inspect_url(start_url, ctx).url
    result = ReconResult(target=start)
    seen: set[str] = set()
    queue: list[tuple[str, int]] = [(start, 0)]
    last = None
    headers_captured = False

    while queue and len(seen) < settings.max_crawl_pages:
        url, depth = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            last = rate_sleep(last)
            resp = fetch(url, ctx)
        except PolicyError as exc:
            result.notes.append(str(exc))
            continue
        result.endpoints.append(ReconEndpoint(url=resp.url, status=resp.status))
        if not headers_captured:
            result.headers = {k: v[:200] for k, v in resp.headers.items()}
            result.technologies.extend(_tech_from_headers(resp.headers))
            headers_captured = True
        ctype = resp.headers.get("content-type", "")
        if "html" in ctype or resp.body[:64].lstrip()[:1] == b"<":
            parsed = parse_html(resp.body)
            if parsed.generator:
                result.technologies.append(f"generator: {parsed.generator[:80]}")
            for action, method, fields in parsed.forms:
                abs_action = inspect_ok(urljoin(resp.url, action or resp.url), ctx)
                if abs_action:
                    result.forms.append(
                        ReconForm(action=abs_action, method=method.upper(), fields=fields)
                    )
                    result.parameters.extend(fields)
            if depth < settings.max_crawl_depth:
                for href in parsed.hrefs:
                    nxt = inspect_ok(urljoin(resp.url, href.split("#", 1)[0]), ctx)
                    if nxt and nxt not in seen:
                        queue.append((nxt, depth + 1))
        query = urlsplit(resp.url).query
        result.parameters.extend(k for k, _ in parse_qsl(query, keep_blank_values=True))

    last = rate_sleep(last)
    for path in INTERESTING:
        candidate = inspect_ok(urljoin(start, path), ctx)
        if not candidate or candidate in seen:
            continue
        try:
            last = rate_sleep(last)
            resp = fetch(candidate, ctx)
        except PolicyError:
            continue
        result.interesting_paths.append(f"{path} ({resp.status})")
        if path in API_HINTS and resp.status == 200:
            result.api_endpoints.append(resp.url)

    result.parameters = sorted(set(result.parameters))
    result.technologies = sorted(set(result.technologies))
    return result


def inspect_ok(url: str, ctx: RequestContext) -> str | None:
    try:
        return inspect_url(url, ctx).url
    except PolicyError:
        return None
