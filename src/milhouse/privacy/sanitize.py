"""Value-safe URL and local-path sanitization before persistence or egress."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import SplitResult, parse_qsl, quote, urlencode, urlsplit, urlunsplit

from milhouse.privacy.pseudonym import PrivacyError, Pseudonymizer

MAX_URL_BYTES = 8_192
MAX_LOCAL_PATH_BYTES = 4_096
MAX_QUERY_FIELDS = 100

_QUERY_KEY_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_QUERY_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{0,128}$")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


@dataclass(frozen=True, slots=True)
class SanitizedUrl:
    value: str
    removed: frozenset[str]


def _validate_text(value: str, *, maximum: int, code: str) -> str:
    if type(value) is not str:
        raise PrivacyError(code, "input must be text")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError(code, "input contains unsupported Unicode")
    normalized = unicodedata.normalize("NFC", value)
    encoded = normalized.encode("utf-8")
    if not encoded or len(encoded) > maximum:
        raise PrivacyError(code, "input is empty or exceeds its byte bound")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise PrivacyError(code, "input contains unsafe control characters")
    return normalized


def _validate_query_allowlist(keys: frozenset[str]) -> frozenset[str]:
    if type(keys) is not frozenset or len(keys) > MAX_QUERY_FIELDS:
        raise PrivacyError("MH_PRIVACY_URL_ALLOWLIST", "query allowlist is invalid")
    for key in keys:
        if type(key) is not str or _QUERY_KEY_PATTERN.fullmatch(key) is None:
            raise PrivacyError("MH_PRIVACY_URL_ALLOWLIST", "query allowlist is invalid")
    return keys


def _normalize_host(hostname: str) -> str:
    try:
        ascii_host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        pass
    else:
        if not ascii_host or len(ascii_host) > 253:
            raise PrivacyError("MH_PRIVACY_URL_HOST", "URL host is invalid")
        return f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    raise PrivacyError("MH_PRIVACY_URL_HOST", "URL host is invalid")


def _split_url(value: str) -> tuple[SplitResult, int | None]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        pass
    else:
        return parsed, port
    raise PrivacyError("MH_PRIVACY_URL", "URL is invalid")


def _parse_query(value: str) -> list[tuple[str, str]]:
    try:
        fields = parse_qsl(
            value,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=MAX_QUERY_FIELDS,
        )
    except ValueError:
        pass
    else:
        return fields
    raise PrivacyError("MH_PRIVACY_URL_QUERY", "URL query is invalid")


def sanitize_url(
    value: str,
    *,
    allowed_query_keys: frozenset[str] = frozenset(),
) -> SanitizedUrl:
    """Strip URL authority secrets and retain only explicitly allowlisted safe query fields."""

    normalized = _validate_text(value, maximum=MAX_URL_BYTES, code="MH_PRIVACY_URL")
    allowlist = _validate_query_allowlist(allowed_query_keys)
    if any(character.isspace() for character in normalized):
        raise PrivacyError("MH_PRIVACY_URL", "URL contains whitespace")
    parsed, port = _split_url(normalized)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise PrivacyError("MH_PRIVACY_URL_SCHEME", "URL scheme is not allowed")
    if parsed.hostname is None:
        raise PrivacyError("MH_PRIVACY_URL_HOST", "URL host is required")
    host = _normalize_host(parsed.hostname)
    if port == 0:
        raise PrivacyError("MH_PRIVACY_URL_PORT", "URL port is invalid")
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"

    if _BAD_PERCENT_ESCAPE.search(parsed.path):
        raise PrivacyError("MH_PRIVACY_URL_PATH", "URL path contains an invalid escape")
    path = quote(parsed.path, safe="/%:@-._~!$&'()*+,;=")
    path = _PERCENT_ESCAPE.sub(lambda match: f"%{match.group(1).upper()}", path)

    removed: set[str] = set()
    if parsed.username is not None or parsed.password is not None:
        removed.add("userinfo")
    if parsed.fragment:
        removed.add("fragment")

    safe_query: list[tuple[str, str]] = []
    if parsed.query:
        fields = _parse_query(parsed.query)
        for key, query_value in fields:
            if key in allowlist and _QUERY_VALUE_PATTERN.fullmatch(query_value) is not None:
                safe_query.append((key, query_value))
            else:
                removed.add("query")
        if not allowlist:
            removed.add("query")
    safe_query.sort()
    query = urlencode(safe_query, doseq=True, quote_via=quote, safe="._~-")
    sanitized = urlunsplit((scheme, host, path, query, ""))
    return SanitizedUrl(value=sanitized, removed=frozenset(removed))


def sanitize_local_path(value: str, *, pseudonymizer: Pseudonymizer) -> str:
    """Replace a local path with a keyed token while retaining no raw path segment."""

    normalized = _validate_text(
        value,
        maximum=MAX_LOCAL_PATH_BYTES,
        code="MH_PRIVACY_PATH",
    )
    normalized = normalized.replace("\\", "/")
    token = pseudonymizer.pseudonymize("path", normalized)
    return f"local-path:{token}"
