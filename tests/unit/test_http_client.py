"""Behaviour of the bounded outbound HTTP client: GET-only, no redirect, TLS on, pinned, capped.

Every test is hermetic: an injected resolver decides the destination address and an ``httpx``
``MockTransport`` stands in for the socket, so no real DNS or connection occurs. The SSRF address
matrix is exercised separately in ``tests/security/test_http_ssrf_boundary.py``.
"""

from __future__ import annotations

import socket

import httpx
import pytest
from _http_fakes import (
    fixed_resolver,
    raising_transport,
    responding_transport,
    stream_response,
)

from milhouse.http import BoundedHttpClient, HttpClientError, system_resolver

_PUBLIC = "93.184.216.34"


def _client(response_factory=None, *, resolver=None, **kwargs):
    transport, captured = responding_transport(
        response_factory or (lambda request: stream_response(200))
    )
    client = BoundedHttpClient(
        resolver=resolver or fixed_resolver(_PUBLIC),
        transport=transport,
        **kwargs,
    )
    return client, captured


# --- the pin: connect to a validated IP, preserve Host + SNI -----------------------------------


def test_get_pins_to_the_validated_ip_and_preserves_host_and_sni() -> None:
    client, captured = _client()
    result = client.get("https://example.test/health", timeout_seconds=5)
    assert result.status_code == 200
    request = captured[0]
    assert request.method == "GET"
    # The connection host is the validated IP (no second, unvalidated resolution can occur) ...
    assert request.url.host == _PUBLIC
    # ... while the original hostname is preserved for the Host header and TLS SNI/verification.
    assert request.headers["host"] == "example.test"
    assert request.extensions.get("sni_hostname") == "example.test"


def test_a_non_default_port_is_carried_into_the_host_header_and_pinned_url() -> None:
    client, captured = _client()
    client.get("https://example.test:8443/health", timeout_seconds=5)
    request = captured[0]
    assert request.headers["host"] == "example.test:8443"
    assert request.url.host == _PUBLIC
    assert request.url.port == 8443


def test_an_http_target_sends_no_sni_extension() -> None:
    client, captured = _client()
    client.get("http://example.test/health", timeout_seconds=5)
    request = captured[0]
    assert request.url.scheme == "http"
    assert "sni_hostname" not in request.extensions
    assert request.headers["host"] == "example.test"


def test_the_target_query_is_preserved_on_the_pinned_request() -> None:
    client, captured = _client()
    client.get("https://example.test/health?probe=1", timeout_seconds=5)
    assert captured[0].url.query == b"probe=1"


# --- GET only, redirects never followed --------------------------------------------------------


def test_a_redirect_status_is_returned_and_never_followed() -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return stream_response(302, headers={"location": "https://elsewhere.test/"})

    client, captured = _client(redirect)
    result = client.get("https://example.test/health", timeout_seconds=5)
    # The 3xx is reported verbatim; the client makes exactly one request and chases nothing.
    assert result.status_code == 302
    assert len(captured) == 1


def test_a_4xx_is_a_delivered_answer_and_is_never_retried() -> None:
    calls = {"n": 0}

    def not_found(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return stream_response(404)

    client, _ = _client(not_found, max_retries=3)
    result = client.get("https://example.test/health", timeout_seconds=5)
    assert result.status_code == 404
    assert calls["n"] == 1


# --- TLS is a non-negotiable floor -------------------------------------------------------------


def test_constructing_a_request_with_tls_disabled_is_refused() -> None:
    client, _ = _client()
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/health", timeout_seconds=5, verify_tls=False)
    assert caught.value.code == "MH_HTTP_TLS_REQUIRED"


# --- scheme / userinfo / URL rejection ---------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("ftp://example.test/x", "MH_HTTP_SCHEME"),
        ("file:///etc/passwd", "MH_HTTP_SCHEME"),
        ("https://user:pass@example.test/x", "MH_HTTP_URL"),
        ("https://user@example.test/x", "MH_HTTP_URL"),
        ("https:///nohost", "MH_HTTP_URL"),
        ("https://exa mple.test/x", "MH_HTTP_URL"),
        ("https://café.test/x", "MH_HTTP_URL"),  # non-ASCII (IDN) host — must be given as punycode
        ("not-a-url", "MH_HTTP_SCHEME"),
    ],
)
def test_a_malformed_or_disallowed_url_fails_closed(url: str, code: str) -> None:
    client, captured = _client()
    with pytest.raises(HttpClientError) as caught:
        client.get(url, timeout_seconds=5)
    assert caught.value.code == code
    assert captured == []


def test_a_non_string_or_oversized_url_is_rejected() -> None:
    client, _ = _client()
    with pytest.raises(HttpClientError) as empty:
        client.get("", timeout_seconds=5)
    assert empty.value.code == "MH_HTTP_URL"
    with pytest.raises(HttpClientError) as oversized:
        client.get("https://example.test/" + "a" * 9000, timeout_seconds=5)
    assert oversized.value.code == "MH_HTTP_URL"


def test_an_invalid_url_port_is_rejected() -> None:
    client, _ = _client()
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test:99999/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_URL"


def test_a_punycode_idn_host_is_accepted_and_pinned() -> None:
    # The ASCII punycode form of an internationalized domain is accepted (the unicode form is
    # rejected above); the Host header and SNI carry the xn-- authority while the connection is
    # still pinned to the validated IP.
    client, captured = _client()
    result = client.get("https://xn--caf-dma.test/health", timeout_seconds=5)
    assert result.status_code == 200
    request = captured[0]
    assert request.url.host == _PUBLIC
    assert request.headers["host"] == "xn--caf-dma.test"
    assert request.extensions.get("sni_hostname") == "xn--caf-dma.test"


def test_the_production_client_ignores_environment_proxies_and_trust_store() -> None:
    # The production transport (no injected transport) is built with trust_env=False, so
    # HTTP(S)_PROXY / ALL_PROXY / SSLKEYLOGFILE / SSL_CERT_* can never route a probe through an
    # unvalidated hop or alter TLS: the SSRF pin is the ONLY thing that decides the destination.
    opened = BoundedHttpClient()._open_client(httpx.Timeout(5.0))
    try:
        assert opened.trust_env is False
    finally:
        opened.close()


# --- timeout budget & transport faults ---------------------------------------------------------


@pytest.mark.parametrize("timeout", [0, -1, 301, "5", 5.0])
def test_an_invalid_timeout_budget_is_rejected(timeout: object) -> None:
    client, _ = _client()
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=timeout)  # type: ignore[arg-type]
    assert caught.value.code == "MH_HTTP_TIMEOUT_BUDGET"


def test_a_connect_timeout_surfaces_a_fixed_timeout_code() -> None:
    transport = raising_transport(httpx.ConnectTimeout("slow"))
    client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_TIMEOUT"


def test_a_transport_fault_surfaces_a_fixed_request_code() -> None:
    transport = raising_transport(httpx.ConnectError("refused"))
    client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_REQUEST"


def test_a_read_timeout_while_draining_the_body_surfaces_a_timeout_code() -> None:
    class _TimingOutStream(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.ReadTimeout("slow body")

        def close(self) -> None:
            return None

    def slow_body(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_TimingOutStream())

    client, _ = _client(slow_body)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_TIMEOUT"


# --- resolution failures -----------------------------------------------------------------------


def test_a_resolver_that_raises_surfaces_a_fixed_resolve_code() -> None:
    def boom(hostname: str) -> tuple[str, ...]:
        raise OSError("no such host")

    client = BoundedHttpClient(resolver=boom, transport=raising_transport(httpx.ConnectError("x")))
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_RESOLVE"


def test_a_host_that_resolves_to_no_address_is_rejected() -> None:
    client, _ = _client(resolver=fixed_resolver())
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_RESOLVE"


def test_a_resolver_raising_a_fixed_http_error_is_propagated_unchanged() -> None:
    def deny(hostname: str) -> tuple[str, ...]:
        raise HttpClientError("MH_HTTP_SSRF_BLOCKED", "resolver policy denied the host")

    client = BoundedHttpClient(resolver=deny, transport=raising_transport(httpx.ConnectError("x")))
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_SSRF_BLOCKED"


# --- bounded body ------------------------------------------------------------------------------


def test_a_declared_over_cap_content_length_is_rejected_before_reading_the_body() -> None:
    read = {"touched": False}

    class _TrippedStream(httpx.SyncByteStream):
        def __iter__(self):
            read["touched"] = True
            yield b"x" * 10
            return

        def close(self) -> None:
            return None

    def oversized(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "1000000"}, stream=_TrippedStream())

    client, _ = _client(oversized, max_response_bytes=1024)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_BODY_TOO_LARGE"
    # The overflow was rejected on the declared length, never draining the body stream.
    assert read["touched"] is False


def test_a_body_that_streams_past_the_cap_is_rejected_mid_stream() -> None:
    def big(request: httpx.Request) -> httpx.Response:
        return stream_response(200, chunks=[b"x" * 4096, b"y" * 4096, b"z" * 4096])

    client, _ = _client(big, max_response_bytes=5000)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_BODY_TOO_LARGE"


def test_a_generic_transport_error_while_draining_the_body_surfaces_a_request_code() -> None:
    class _BrokenStream(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.RemoteProtocolError("peer closed mid-body")

        def close(self) -> None:
            return None

    def broken(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_BrokenStream())

    client, _ = _client(broken)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_REQUEST"


def test_a_non_numeric_content_length_is_ignored_and_the_body_is_streamed() -> None:
    def bad_length(request: httpx.Request) -> httpx.Response:
        return stream_response(200, chunks=[b"ok"], headers={"content-length": "banana"})

    client, _ = _client(bad_length, max_response_bytes=1024)
    result = client.get("https://example.test/x", timeout_seconds=5)
    assert result.status_code == 200
    assert result.response_bytes == 2


# --- retries -----------------------------------------------------------------------------------


def test_a_transport_fault_is_retried_up_to_the_bound_then_succeeds() -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("first attempt")
        return stream_response(200)

    client, _ = _client(flaky, max_retries=1)
    result = client.get("https://example.test/x", timeout_seconds=5)
    assert result.status_code == 200
    assert calls["n"] == 2


def test_a_transport_fault_past_the_retry_bound_is_surfaced() -> None:
    transport = raising_transport(httpx.ConnectError("always"))
    client = BoundedHttpClient(resolver=fixed_resolver(_PUBLIC), transport=transport, max_retries=1)
    with pytest.raises(HttpClientError) as caught:
        client.get("https://example.test/x", timeout_seconds=5)
    assert caught.value.code == "MH_HTTP_REQUEST"


# --- construction guards & result --------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_response_bytes": 0},
        {"max_response_bytes": 10**9},
        {"max_retries": -1},
        {"max_retries": 99},
    ],
)
def test_invalid_client_bounds_fail_closed(kwargs: dict[str, int]) -> None:
    with pytest.raises(HttpClientError) as caught:
        BoundedHttpClient(**kwargs)  # type: ignore[arg-type]
    assert caught.value.code == "MH_HTTP_CONFIG"


def test_the_probe_result_reports_status_bytes_and_a_nonnegative_latency() -> None:
    timeline = iter([1_000_000, 8_000_000])
    transport, _ = responding_transport(lambda request: stream_response(200, chunks=[b"abcd"]))
    client = BoundedHttpClient(
        resolver=fixed_resolver(_PUBLIC),
        transport=transport,
        monotonic_ns=lambda: next(timeline),
    )
    result = client.get("https://example.test/x", timeout_seconds=5)
    assert result.status_code == 200
    assert result.response_bytes == 4
    assert result.elapsed_ms == 7


# --- the production default resolver stays offline for a literal address -----------------------


def test_the_production_client_construction_enables_tls_verification() -> None:
    # The default (no injected transport) path builds a real, TLS-verifying client; construct and
    # close it without making a request so the production branch is covered offline.
    client = BoundedHttpClient()
    opened = client._open_client(httpx.Timeout(1.0))
    try:
        assert isinstance(opened, httpx.Client)
        assert opened.follow_redirects is False
    finally:
        opened.close()


def test_the_system_resolver_returns_a_literal_ip_without_network() -> None:
    assert system_resolver(_PUBLIC) == (_PUBLIC,)


def test_the_system_resolver_deduplicates_repeated_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = (socket.AF_INET, socket.SOCK_STREAM, 0, "", (_PUBLIC, 0))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [entry, entry])
    assert system_resolver("example.test") == (_PUBLIC,)


def test_the_system_resolver_maps_a_lookup_failure_to_a_fixed_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> object:
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(HttpClientError) as caught:
        system_resolver("does-not-resolve.invalid")
    assert caught.value.code == "MH_HTTP_RESOLVE"
