"""Fixed, value-safe error type for the bounded outbound HTTP client (W05, plan section 4.8).

Every outbound-HTTP failure is a stable ``MH_HTTP_*`` code carrying only bounded developer text.
Like the runtime, spool, and storage boundaries, these errors never render a credentialed URL, a
secret, a resolved host or IP, a request path, a raw header, or a machine-local path, so a failure —
including one raised by the SSRF guard against an attacker-controlled target — is always safe to
surface, log, or summarize.
"""

from __future__ import annotations

from milhouse.core.errors import MilhouseError


class HttpClientError(MilhouseError):
    """A fail-closed outbound-HTTP failure carrying a fixed ``MH_HTTP_*`` code.

    Codes: ``MH_HTTP_CONFIG`` (an invalid client bound such as a non-positive body ceiling),
    ``MH_HTTP_URL`` (a malformed URL, embedded userinfo, or a missing host),
    ``MH_HTTP_SCHEME`` (a non ``http``/``https`` scheme), ``MH_HTTP_TLS_REQUIRED`` (a caller asked
    to construct a request with TLS verification disabled), ``MH_HTTP_TIMEOUT_BUDGET`` (an invalid
    request-timeout budget), ``MH_HTTP_RESOLVE`` (host resolution failed or produced no address),
    ``MH_HTTP_SSRF_BLOCKED`` (a resolved address is not globally routable — the SSRF guard tripped),
    ``MH_HTTP_TIMEOUT`` (the request exceeded its timeout budget), ``MH_HTTP_BODY_TOO_LARGE`` (the
    response body exceeded the byte ceiling), and ``MH_HTTP_REQUEST`` (a transport or connection
    fault). The message never carries a URL, secret, resolved host or IP, path, or raw header.
    """


__all__ = ["HttpClientError"]
