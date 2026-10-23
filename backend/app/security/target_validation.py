"""Defensive target-safety checks (docs/security-model.md §2).

This module only *rejects* destinations that must not be scanned (loopback, private
ranges, cloud metadata, credentials-in-URL, non-http schemes). It never probes a
target beyond optional DNS resolution of the hostname.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Cloud instance-metadata endpoints stay blocked even when private targets are allowed.
_METADATA_V4 = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
    }
)
_METADATA_V6 = frozenset({ipaddress.ip_address("fd00:ec2::254")})
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)

Resolver = Callable[[str], Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address]]


class InvalidTargetURL(ValueError):
    """Syntactically unacceptable URL (maps to HTTP 422)."""


@dataclass(frozen=True)
class TargetCheck:
    allowed: bool
    url: str
    host: str
    reason: str = ""


def normalize_url(raw: str) -> str:
    """Canonical http(s) URL: lower-case scheme/host, no userinfo, default path."""
    text = (raw or "").strip()
    if not text:
        raise InvalidTargetURL("URL is empty")
    parts = urlsplit(text)
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise InvalidTargetURL("Only http and https URLs are allowed")
    if parts.username or parts.password:
        raise InvalidTargetURL("Credentials in the URL are not allowed")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise InvalidTargetURL("URL must include a host")
    try:
        port = parts.port
    except ValueError as exc:
        raise InvalidTargetURL("Port is invalid") from exc
    if port is not None and not (1 <= port <= 65535):
        raise InvalidTargetURL("Port is invalid")
    path = parts.path or "/"
    netloc = f"{host}:{port}" if port else host
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def resolve_host(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve a hostname to IP addresses. IPv6 zone ids are stripped."""
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise InvalidTargetURL(f"Host could not be resolved ({exc.errno})") from exc
    for _family, _type, _proto, _canon, sockaddr in infos:
        raw = sockaddr[0].split("%", 1)[0]
        ip = ipaddress.ip_address(raw)
        key = str(ip)
        if key not in seen:
            seen.add(key)
            found.append(ip)
    return found


def _is_metadata(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip in _METADATA_V4 or ip in _METADATA_V6


def _is_restricted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
        return True
    if ip.is_multicast or ip.is_reserved:
        return True
    return ip.version == 4 and ip in _CGNAT


def _host_blocked_before_dns(host: str) -> str | None:
    if host == "localhost" or host.endswith(".localhost"):
        return "Loopback hostnames are not allowed"
    if host in _METADATA_HOSTS:
        return "Cloud metadata hostnames are not allowed"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if _is_metadata(ip):
        return "Cloud metadata addresses are not allowed"
    return None


def check_url(
    raw: str,
    *,
    allow_private: bool,
    allowlist: list[str],
    resolver: Resolver | None = None,
) -> TargetCheck:
    """Resolve the host and decide whether it may be scanned."""
    url = normalize_url(raw)
    host = urlsplit(url).hostname or ""
    if reason := _host_blocked_before_dns(host):
        return TargetCheck(False, url, host, reason)

    allowed_hosts = [h.strip().lower() for h in allowlist if h.strip()]
    if allowed_hosts and host not in allowed_hosts:
        return TargetCheck(False, url, host, "Host is not on the target allowlist")

    resolve = resolver or resolve_host
    try:
        addresses = list(resolve(host))
    except InvalidTargetURL as exc:
        return TargetCheck(False, url, host, str(exc) or "Host could not be resolved")
    except OSError:
        return TargetCheck(False, url, host, "Host could not be resolved")
    if not addresses:
        return TargetCheck(False, url, host, "Host could not be resolved")

    for ip in addresses:
        if _is_metadata(ip):
            return TargetCheck(False, url, host, "Cloud metadata addresses are not allowed")
        if _is_restricted(ip) and not allow_private:
            return TargetCheck(
                False,
                url,
                host,
                "Private, loopback, link-local or reserved addresses are not allowed",
            )
    return TargetCheck(True, url, host, "")


def in_scope(url: str, scope: dict) -> bool:
    """True if url's host is in scope['allowed_hosts'] and its path matches a prefix."""
    try:
        normalised = normalize_url(url)
    except InvalidTargetURL:
        return False
    parts = urlsplit(normalised)
    host = (parts.hostname or "").lower()
    allowed = [str(h).lower() for h in (scope.get("allowed_hosts") or [])]
    if host not in allowed:
        return False
    prefixes = list(scope.get("path_prefixes") or ["/"])
    path = parts.path or "/"
    return any(_path_matches(path, prefix) for prefix in prefixes)


def _path_matches(path: str, prefix: str) -> bool:
    if not prefix or prefix == "/":
        return True
    stem = prefix.rstrip("/") or "/"
    return path == stem or path.startswith(stem + "/")
