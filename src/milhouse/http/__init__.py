"""The bounded, SSRF- and TLS-guarded outbound HTTP surface shared by collectors (W05).

Collectors never construct an :mod:`httpx` client directly. They use :class:`BoundedHttpClient`,
which makes exactly one GET, never follows a redirect, always verifies TLS, refuses every non-public
destination through an injectable resolver, and caps the response body it reads. Every failure is a
fixed :class:`HttpClientError` (``MH_HTTP_*``) that renders no URL, secret, resolved host, or path.
"""

from __future__ import annotations

from milhouse.http.client import (
    DEFAULT_MAX_RESPONSE_BYTES,
    BoundedHttpClient,
    HttpProbeResult,
    Resolver,
    system_resolver,
)
from milhouse.http.errors import HttpClientError

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "BoundedHttpClient",
    "HttpClientError",
    "HttpProbeResult",
    "Resolver",
    "system_resolver",
]
