"""A bounded, SSRF- and TLS-guarded outbound HTTP client (W05, plan section 4.8).

This is the single outbound-HTTP surface every collector uses. It is deliberately small and
fail-closed: it makes exactly one ``GET`` per call, never follows a redirect, always verifies TLS,
refuses every non-public destination, and caps the response body it reads. Every failure is a fixed
:class:`~milhouse.http.errors.HttpClientError` (``MH_HTTP_*``) that never renders a credentialed
URL, a secret, a resolved host or IP, a request path, or a raw header.

SSRF guard (the centerpiece)
----------------------------
Before connecting, the client resolves the target host to its IP address(es) through an
**injectable resolver** (no network in tests) and refuses if *any* address is not globally routable.
Classification uses :mod:`ipaddress` plus explicit ranges: it rejects loopback, private (RFC 1918),
link-local (including the ``169.254.169.254`` cloud-metadata address), reserved, multicast,
unspecified, IPv4 CGNAT (``100.64.0.0/10``), IPv6 ULA (``fc00::/7``), and any IPv4-mapped, IPv4-
compatible, 6to4, or Teredo IPv6 address whose embedded IPv4 is itself non-public; only an address
that is additionally :attr:`ipaddress.IPv4Address.is_global` is accepted.

DNS-rebinding mitigation
------------------------
The client validates *all* resolved addresses, then **pins** the connection to a validated IP: the
request URL host is rewritten to that literal IP so no second, unvalidated resolution can occur
between check and connect, while the original ``Host`` header and TLS SNI/certificate hostname are
preserved (via the ``sni_hostname`` request extension). This closes the classic
resolve-then-connect rebinding window. The one residual assumption is that the injected resolver
returns the addresses the OS would; the default resolver is the OS resolver, so production is safe.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from milhouse.http.errors import HttpClientError

#: A resolver maps a hostname to an ordered tuple of textual IP addresses. It is injectable so the
#: SSRF guard is exercised entirely offline; the production default is the OS resolver.
Resolver = Callable[[str], Sequence[str]]

#: Default response-body ceiling. A canary needs only the status line and headers, so the client
#: caps the body it reads and treats an overflow as a fixed error rather than streaming unbounded.
DEFAULT_MAX_RESPONSE_BYTES = 65_536
_MAX_RESPONSE_BYTES_CEILING = 8 * 1024 * 1024
_MAX_RETRIES_CEILING = 8
_MAX_URL_BYTES = 8_192
_MIN_TIMEOUT_SECONDS = 1
_MAX_TIMEOUT_SECONDS = 300
_READ_CHUNK_BYTES = 8_192

#: Explicit ranges that :mod:`ipaddress` may not fold into ``is_private`` on every supported
#: runtime, rejected here for defence in depth alongside the ``is_global`` gate.
_IPV4_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_IPV6_ULA = ipaddress.ip_network("fc00::/7")

_MonotonicNs = Callable[[], int]


@dataclass(frozen=True, slots=True)
class HttpProbeResult:
    """The privacy-safe outcome of one probe: no body, no raw headers, no destination text."""

    status_code: int
    elapsed_ms: int
    response_bytes: int


@dataclass(frozen=True, slots=True)
class _ParsedTarget:
    """One validated request target with its host pieces already separated for pinning."""

    scheme: str
    host: str
    host_authority: str
    port: int
    path: str


def system_resolver(hostname: str) -> tuple[str, ...]:
    """Resolve a hostname to every A/AAAA address through the OS resolver (production default)."""

    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        raise HttpClientError("MH_HTTP_RESOLVE", "the target host could not be resolved") from None
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    return tuple(addresses)


def _embedded_ipv4(address: ipaddress.IPv6Address) -> tuple[ipaddress.IPv4Address, ...]:
    """Return every IPv4 address an IPv6 form embeds (mapped, compatible, 6to4, Teredo)."""

    embedded: list[ipaddress.IPv4Address] = []
    mapped = address.ipv4_mapped
    if mapped is not None:
        embedded.append(mapped)
    sixtofour = address.sixtofour
    if sixtofour is not None:
        embedded.append(sixtofour)
    teredo = address.teredo
    if teredo is not None:
        embedded.extend(teredo)
    packed = int(address)
    # A deprecated IPv4-compatible address ``::a.b.c.d`` carries the IPv4 in its low 32 bits with an
    # all-zero prefix; ``::`` and ``::1`` are excluded (already rejected as unspecified/loopback).
    if packed >> 32 == 0 and packed not in (0, 1):
        embedded.append(ipaddress.IPv4Address(packed & 0xFFFFFFFF))
    return tuple(embedded)


def _is_globally_routable(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return whether one concrete address is a public, globally-routable unicast address."""

    # The explicit CGNAT/ULA ranges are checked first so they stay the decisive rejection even on a
    # runtime whose ``is_private`` omits them (IPv4 CGNAT notably is not private-flagged).
    if address.version == 4 and address in _IPV4_CGNAT:
        return False
    if address.version == 6 and address in _IPV6_ULA:
        return False
    if (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        return False
    return bool(address.is_global)


def _is_public_address(text: str) -> bool:
    """Return whether a textual address, and every IPv4 an IPv6 form embeds, is globally routable.

    The embedded-IPv4 decode is checked first and is the deciding rejection for any IPv4-mapped,
    IPv4-compatible, 6to4, or Teredo IPv6 whose underlying IPv4 is not public, so a v6 literal can
    never launder a private v4 destination past the guard.
    """

    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        for embedded in _embedded_ipv4(address):
            if not _is_globally_routable(embedded):
                return False
    return _is_globally_routable(address)


def _select_pinned_address(addresses: Sequence[str]) -> str:
    """Validate every resolved address and return the canonical first one to pin the connection."""

    if not addresses:
        raise HttpClientError("MH_HTTP_RESOLVE", "the target host resolved to no address")
    for text in addresses:
        if not _is_public_address(text):
            raise HttpClientError(
                "MH_HTTP_SSRF_BLOCKED", "the target resolves to a non-public address"
            )
    return ipaddress.ip_address(addresses[0]).compressed


def _has_unsafe_url_character(url: str) -> bool:
    """Return whether the URL carries a control character or whitespace (header-injection safe)."""

    return any(
        ord(character) < 0x20 or ord(character) == 0x7F or character.isspace() for character in url
    )


def _parse_target(url: str) -> _ParsedTarget:
    """Parse and fail-closed validate a request URL into its pinnable pieces."""

    if type(url) is not str or not url or len(url.encode("utf-8")) > _MAX_URL_BYTES:
        raise HttpClientError("MH_HTTP_URL", "a bounded target URL is required")
    if _has_unsafe_url_character(url):
        raise HttpClientError("MH_HTTP_URL", "the target URL contains unsafe characters")
    try:
        split = urlsplit(url)
        port = split.port
    except ValueError:
        raise HttpClientError("MH_HTTP_URL", "the target URL is invalid") from None
    scheme = split.scheme.lower()
    if scheme not in ("http", "https"):
        raise HttpClientError("MH_HTTP_SCHEME", "only http and https targets are permitted")
    if split.username is not None or split.password is not None:
        raise HttpClientError("MH_HTTP_URL", "credentials in the target URL are not permitted")
    host = split.hostname
    if not host:
        raise HttpClientError("MH_HTTP_URL", "the target URL has no host")
    if not host.isascii():
        # A non-ASCII (IDN) host would raise an uncaught UnicodeEncodeError when built into the Host
        # header, escaping the MH_HTTP_* mapping. Require the caller to supply the punycode (xn--)
        # form so the resolver, Host header, and TLS SNI all agree on one ASCII authority.
        raise HttpClientError(
            "MH_HTTP_URL",
            "the target host must be ASCII (use punycode for an internationalized name)",
        )
    resolved_port = port if port is not None else (443 if scheme == "https" else 80)
    host_authority = f"[{host}]" if ":" in host else host
    path = split.path or "/"
    if split.query:
        path = f"{path}?{split.query}"
    return _ParsedTarget(
        scheme=scheme,
        host=host,
        host_authority=host_authority,
        port=resolved_port,
        path=path,
    )


def _build_pinned_request(target: _ParsedTarget, pinned_ip: str) -> tuple[str, str]:
    """Rewrite the connect host to the validated IP while preserving the original Host authority."""

    address = ipaddress.ip_address(pinned_ip)
    host_for_url = f"[{pinned_ip}]" if address.version == 6 else pinned_ip
    default_port = 443 if target.scheme == "https" else 80
    if target.port == default_port:
        host_header = target.host_authority
    else:
        host_header = f"{target.host_authority}:{target.port}"
    request_url = f"{target.scheme}://{host_for_url}:{target.port}{target.path}"
    return request_url, host_header


class BoundedHttpClient:
    """A small, fail-closed outbound HTTP client: GET-only, no redirects, TLS on, SSRF-guarded.

    The ``transport`` argument is a TEST-ONLY injection seam (an ``httpx.MockTransport`` so the SSRF
    guard runs with no socket); it bypasses the production ``verify=True`` / ``trust_env=False``
    floor, so production callers MUST leave it ``None`` (the default) and rely on the built-in real
    transport.
    """

    __slots__ = ("_max_response_bytes", "_max_retries", "_monotonic_ns", "_resolver", "_transport")

    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        transport: httpx.BaseTransport | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_retries: int = 0,
        monotonic_ns: _MonotonicNs | None = None,
    ) -> None:
        if (
            type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= _MAX_RESPONSE_BYTES_CEILING
        ):
            raise HttpClientError("MH_HTTP_CONFIG", "the response byte ceiling is invalid")
        if type(max_retries) is not int or not 0 <= max_retries <= _MAX_RETRIES_CEILING:
            raise HttpClientError("MH_HTTP_CONFIG", "the retry bound is invalid")
        self._resolver: Resolver = system_resolver if resolver is None else resolver
        self._transport = transport
        self._max_response_bytes = max_response_bytes
        self._max_retries = max_retries
        self._monotonic_ns: _MonotonicNs = (
            time.monotonic_ns if monotonic_ns is None else monotonic_ns
        )

    def get(
        self,
        url: str,
        *,
        timeout_seconds: int,
        verify_tls: bool = True,
    ) -> HttpProbeResult:
        """Perform one bounded, SSRF-guarded GET and return only a privacy-safe probe result."""

        if verify_tls is not True:
            raise HttpClientError("MH_HTTP_TLS_REQUIRED", "TLS verification cannot be disabled")
        timeout = self._request_timeout(timeout_seconds)
        target = _parse_target(url)
        attempts = 0
        while True:
            attempts += 1
            pinned_ip = _select_pinned_address(self._resolve(target.host))
            try:
                return self._probe(target, pinned_ip=pinned_ip, timeout=timeout)
            except HttpClientError as error:
                # Only a transport/connection fault is retried, and never a received response
                # (a 4xx/5xx is a delivered answer, not a fault). Re-resolution and re-validation
                # happen on every attempt, so a retry cannot slip past the SSRF guard.
                if error.code != "MH_HTTP_REQUEST" or attempts > self._max_retries:
                    raise

    def _request_timeout(self, timeout_seconds: int) -> httpx.Timeout:
        if (
            type(timeout_seconds) is not int
            or not _MIN_TIMEOUT_SECONDS <= timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise HttpClientError(
                "MH_HTTP_TIMEOUT_BUDGET", "a bounded positive request timeout is required"
            )
        return httpx.Timeout(float(timeout_seconds))

    def _resolve(self, hostname: str) -> tuple[str, ...]:
        try:
            return tuple(self._resolver(hostname))
        except HttpClientError:
            raise
        except Exception:
            raise HttpClientError(
                "MH_HTTP_RESOLVE", "the target host could not be resolved"
            ) from None

    def _open_client(self, timeout: httpx.Timeout) -> httpx.Client:
        if self._transport is not None:
            return httpx.Client(transport=self._transport, timeout=timeout, follow_redirects=False)
        # Production path: a real transport with TLS verification unconditionally enabled, and
        # trust_env=False so the SSRF pin is the ONLY thing that decides the destination. Without it
        # httpx honours HTTP(S)_PROXY/ALL_PROXY (routing a probe through an unvalidated — possibly
        # loopback/internal — proxy hop, voiding the pin) and the SSLKEYLOGFILE/SSL_CERT_* env vars
        # (dumping TLS keys or swapping the trust store); a hardened client honours none of them.
        return httpx.Client(verify=True, timeout=timeout, follow_redirects=False, trust_env=False)

    def _probe(
        self,
        target: _ParsedTarget,
        *,
        pinned_ip: str,
        timeout: httpx.Timeout,
    ) -> HttpProbeResult:
        request_url, host_header = _build_pinned_request(target, pinned_ip)
        extensions = {"sni_hostname": target.host} if target.scheme == "https" else {}
        request = httpx.Request(
            "GET", request_url, headers={"Host": host_header}, extensions=extensions
        )
        started = self._monotonic_ns()
        with self._open_client(timeout) as client:
            try:
                response = client.send(request, stream=True)
            except httpx.TimeoutException:
                raise HttpClientError("MH_HTTP_TIMEOUT", "the outbound request timed out") from None
            except httpx.HTTPError:
                raise HttpClientError("MH_HTTP_REQUEST", "the outbound request failed") from None
            try:
                size = self._drain_capped(response)
                status = response.status_code
            finally:
                response.close()
        elapsed_ms = max(0, (self._monotonic_ns() - started) // 1_000_000)
        return HttpProbeResult(status_code=status, elapsed_ms=elapsed_ms, response_bytes=size)

    def _drain_capped(self, response: httpx.Response) -> int:
        """Read the raw body up to the ceiling, rejecting an overflow without draining it all."""

        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_bytes = int(declared)
            except ValueError:
                declared_bytes = -1
            if declared_bytes > self._max_response_bytes:
                raise HttpClientError(
                    "MH_HTTP_BODY_TOO_LARGE", "the response body exceeded the byte ceiling"
                )
        total = 0
        try:
            for chunk in response.iter_raw(_READ_CHUNK_BYTES):
                total += len(chunk)
                if total > self._max_response_bytes:
                    raise HttpClientError(
                        "MH_HTTP_BODY_TOO_LARGE", "the response body exceeded the byte ceiling"
                    )
        except httpx.TimeoutException:
            raise HttpClientError("MH_HTTP_TIMEOUT", "the outbound request timed out") from None
        except httpx.HTTPError:
            raise HttpClientError("MH_HTTP_REQUEST", "the outbound request failed") from None
        return total


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "BoundedHttpClient",
    "HttpProbeResult",
    "Resolver",
    "system_resolver",
]
