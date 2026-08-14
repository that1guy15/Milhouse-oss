"""Offline fakes for the W05 bounded HTTP client and site-canary suites (not collected by pytest).

Provides a lazy-streaming :mod:`httpx` response builder (so the client's streaming byte-cap runs the
same code path a real transport would), a recording ``MockTransport`` wrapper, injectable resolvers,
and small handlers that raise transport/timeout faults — all without opening a real socket.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence

import httpx


class _ChunkStream(httpx.SyncByteStream):
    """A lazy response body so ``iter_raw`` streams (a ``content=`` response is pre-consumed)."""

    def __init__(self, chunks: Sequence[bytes]) -> None:
        self._chunks = tuple(chunks)

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks

    def close(self) -> None:  # pragma: no cover - nothing to release for an in-memory stream
        return None


def stream_response(
    status_code: int,
    *,
    chunks: Sequence[bytes] = (b"ok",),
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a lazily-streamed response with an explicit chunk sequence and headers."""

    return httpx.Response(status_code, headers=dict(headers or {}), stream=_ChunkStream(chunks))


def responding_transport(
    response_factory: Callable[[httpx.Request], httpx.Response],
) -> tuple[httpx.MockTransport, list[httpx.Request]]:
    """A mock transport plus the list it appends each handled request to (for pin assertions)."""

    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return response_factory(request)

    return httpx.MockTransport(handler), captured


def raising_transport(error: BaseException) -> httpx.MockTransport:
    """A mock transport whose every request raises the given transport/timeout error."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise error

    return httpx.MockTransport(handler)


def fixed_resolver(*addresses: str) -> Callable[[str], tuple[str, ...]]:
    """An injectable resolver that returns the same textual addresses for any hostname."""

    def resolve(hostname: str) -> tuple[str, ...]:
        return tuple(addresses)

    return resolve
