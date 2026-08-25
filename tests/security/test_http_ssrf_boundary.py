"""Exhaustive SSRF boundary for the bounded HTTP client: every non-public target is refused.

The client resolves through an injected resolver, so this drives the real guard with no network: a
hostname is made to "resolve" to each hostile address class and the client must fail closed with a
fixed ``MH_HTTP_SSRF_BLOCKED`` code before any transport is used, while a genuinely public address
is allowed through to the (mock) transport. Non-http(s) schemes and embedded userinfo are rejected.
"""

from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest

from milhouse.http import BoundedHttpClient, HttpClientError

pytestmark = pytest.mark.security

_PUBLIC_V4 = "93.184.216.34"
_PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"
# A Teredo address (2001:0000::/32) whose obfuscated client IPv4 decodes to private 10.0.0.5, so the
# embedded-IPv4 decode must reject it even though the v6 literal is not obviously private.
_TEREDO_PRIVATE_CLIENT = "2001:0:4137:9e76::f5ff:fffa"

_NON_PUBLIC_ADDRESSES = [
    "127.0.0.1",  # IPv4 loopback
    "::1",  # IPv6 loopback
    "169.254.169.254",  # link-local cloud metadata
    "10.0.0.5",  # RFC 1918 private
    "172.16.31.9",  # RFC 1918 private
    "192.168.1.10",  # RFC 1918 private
    "100.64.7.7",  # IPv4 CGNAT 100.64.0.0/10
    "fc00::1",  # IPv6 ULA fc00::/7
    "fd12:3456::1",  # IPv6 ULA fc00::/7
    "0.0.0.0",  # unspecified
    "::",  # IPv6 unspecified
    "::ffff:127.0.0.1",  # IPv4-mapped IPv6 decoding to loopback
    "::7f00:1",  # IPv4-compatible IPv6 decoding to 127.0.0.1
    "2002:7f00:1::",  # 6to4 embedding 127.0.0.1
    _TEREDO_PRIVATE_CLIENT,
    "not-an-ip",  # an unparseable address is treated as non-public
]


class _Stream(httpx.SyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks

    def close(self) -> None:
        return None


def _ok_transport() -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, stream=_Stream((b"ok",))))


def _client_resolving_to(*addresses: str) -> BoundedHttpClient:
    return BoundedHttpClient(resolver=lambda hostname: tuple(addresses), transport=_ok_transport())


@pytest.mark.parametrize("address", _NON_PUBLIC_ADDRESSES)
def test_a_non_public_resolved_address_is_refused_fail_closed(address: str) -> None:
    client = _client_resolving_to(address)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://target.test/health", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_SSRF_BLOCKED"


def test_a_public_hostname_that_resolves_to_a_private_ip_is_refused() -> None:
    # The classic DNS-based SSRF: a public-looking name resolves to an internal address.
    client = _client_resolving_to("10.0.0.5")
    with pytest.raises(HttpClientError) as caught:
        client.get("https://internal-facing.example/health", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_SSRF_BLOCKED"


def test_all_resolved_addresses_are_validated_not_just_the_first() -> None:
    # A public first address must not smuggle a private second address past the guard.
    client = _client_resolving_to(_PUBLIC_V4, "10.0.0.5")
    with pytest.raises(HttpClientError) as caught:
        client.get("https://target.test/health", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_SSRF_BLOCKED"


@pytest.mark.parametrize("address", [_PUBLIC_V4, _PUBLIC_V6])
def test_a_genuinely_public_address_is_allowed(address: str) -> None:
    client = _client_resolving_to(address)
    result = client.get("https://target.test/health", timeout_seconds=5)
    assert result.status_code == 200


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://target.test/x", "MH_HTTP_SCHEME"),
        ("gopher://target.test/x", "MH_HTTP_SCHEME"),
        ("file:///etc/shadow", "MH_HTTP_SCHEME"),
        ("https://admin:secret@target.test/x", "MH_HTTP_URL"),
    ],
)
def test_a_disallowed_scheme_or_embedded_userinfo_is_refused(url: str, code: str) -> None:
    client = _client_resolving_to(_PUBLIC_V4)
    with pytest.raises(HttpClientError) as caught:
        client.get(url, timeout_seconds=5)
    assert caught.value.code == code
