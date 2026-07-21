"""Layered, bounded free-text redaction for untrusted operational evidence."""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from milhouse.core.immutable import freeze_dict
from milhouse.privacy.pseudonym import PrivacyError, Pseudonymizer
from milhouse.privacy.sanitize import sanitize_local_path, sanitize_url

MAX_REDACTION_INPUT_BYTES = 65_536
MAX_REDACTED_TEXT_BYTES = 10_240
MAX_KNOWN_SECRETS = 128
MIN_KNOWN_SECRET_BYTES = 8
MAX_KNOWN_SECRET_BYTES = 4_096
MAX_URLS_PER_TEXT = 100

_REDACTION_POLICY_VERSION = 1
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
_CREDENTIAL_HEADER = re.compile(
    r"^[ \t]*(?P<name>authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|x-auth-token)\s*:[^\n]*$",
    re.IGNORECASE | re.MULTILINE,
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?P<name>api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|token)\b(?P<separator>\s*[:=]\s*)"
    r"[^\n]*",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)+[\w-]{2,63}",
    re.IGNORECASE,
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_BRACKETED_IPV6 = re.compile(r"\[[0-9A-Fa-f:.%]+\]")
_PHONE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{3}\)?[ .-]?)"
    r"\d{3}[ .-]\d{4}(?!\w)"
)
_POSIX_PATH = re.compile(
    r"(?<![\w:])/(?:Users|Volumes|etc|home|opt|private|srv|tmp|var)/"
    r"[^\s<>\"'`]+"
)
_WINDOWS_PATH = re.compile(r"(?<!\w)[A-Za-z]:[\\/][^\s<>\"'`]+")
_UNC_PATH = re.compile(r"\\\\[A-Za-z0-9_.-]+\\[^\s<>\"'`]+")
_PERCENT_ESCAPE = re.compile(r"%[0-9A-F]{2}")
_TRAILING_URL_PUNCTUATION = ".,;:!?)}"


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """One privacy-safe text result plus non-sensitive rule-category counts."""

    value: str
    counts: dict[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "counts", freeze_dict(dict(self.counts)))

    @property
    def changed(self) -> bool:
        return bool(self.counts)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _increment(counts: dict[str, int], category: str, amount: int = 1) -> None:
    counts[category] = counts.get(category, 0) + amount


def _normalize_text(value: str) -> tuple[str, int]:
    if type(value) is not str:
        raise PrivacyError("MH_PRIVACY_REDACT_TYPE", "redaction input must be text")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError(
            "MH_PRIVACY_REDACT_UNICODE",
            "redaction input contains unsupported Unicode",
        )
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_REDACTION_INPUT_BYTES:
        raise PrivacyError(
            "MH_PRIVACY_REDACT_INPUT_LARGE",
            "redaction input exceeds the raw byte bound",
        )
    removed_controls = 0
    cleaned: list[str] = []
    for character in normalized:
        codepoint = ord(character)
        if character in "\n\t" or (
            codepoint >= 0x20 and codepoint != 0x7F and unicodedata.category(character) != "Cf"
        ):
            cleaned.append(character)
        else:
            removed_controls += 1
    return "".join(cleaned), removed_controls


def _validate_known_secret(value: str) -> str:
    if type(value) is not str:
        raise PrivacyError(
            "MH_PRIVACY_SECRET_TYPE",
            "known redaction values must be text",
        )
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError(
            "MH_PRIVACY_SECRET_UNICODE",
            "known redaction value contains unsupported Unicode",
        )
    normalized = unicodedata.normalize("NFC", value)
    encoded = normalized.encode("utf-8")
    if not MIN_KNOWN_SECRET_BYTES <= len(encoded) <= MAX_KNOWN_SECRET_BYTES:
        raise PrivacyError(
            "MH_PRIVACY_SECRET_LENGTH",
            "known redaction value is outside the credential byte bounds",
        )
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized):
        raise PrivacyError(
            "MH_PRIVACY_SECRET_CONTROL",
            "known redaction value contains unsupported controls",
        )
    return normalized


def _secret_variants(value: str) -> set[str]:
    encoded = value.encode("utf-8")
    percent = quote(value, safe="")
    plus = quote_plus(value, safe="")
    double_percent = quote(percent, safe="")

    def lowercase_escapes(encoded_value: str) -> str:
        return _PERCENT_ESCAPE.sub(lambda match: match.group(0).lower(), encoded_value)

    variants = {
        value,
        percent,
        lowercase_escapes(percent),
        plus,
        lowercase_escapes(plus),
        double_percent,
        lowercase_escapes(double_percent),
        quote(lowercase_escapes(percent), safe=""),
        base64.b64encode(encoded).decode("ascii"),
        base64.b64encode(encoded).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(encoded).decode("ascii"),
        base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        encoded.hex(),
        encoded.hex().upper(),
        html.escape(value, quote=True),
        json.dumps(value, ensure_ascii=True)[1:-1],
    }
    return {variant for variant in variants if variant}


class LayeredRedactor:
    """Apply allowlist-independent redaction without exposing registered values."""

    __slots__ = ("__known_secret_count", "__pseudonymizer", "__secret_variants")

    def __init__(
        self,
        pseudonymizer: Pseudonymizer,
        *,
        known_secrets: tuple[str, ...] = (),
    ) -> None:
        if type(pseudonymizer) is not Pseudonymizer:
            raise PrivacyError(
                "MH_PRIVACY_REDACTOR_PSEUDONYMIZER",
                "redactor requires a pseudonymizer",
            )
        if type(known_secrets) is not tuple or len(known_secrets) > MAX_KNOWN_SECRETS:
            raise PrivacyError(
                "MH_PRIVACY_SECRET_SET",
                "known redaction value set is invalid or too large",
            )
        normalized = tuple(_validate_known_secret(value) for value in known_secrets)
        if len(normalized) != len(set(normalized)):
            raise PrivacyError(
                "MH_PRIVACY_SECRET_DUPLICATE",
                "known redaction value set contains duplicates",
            )
        variants: set[str] = set()
        for value in normalized:
            variants.update(_secret_variants(value))
        self.__pseudonymizer = pseudonymizer
        self.__known_secret_count = len(normalized)
        self.__secret_variants = tuple(sorted(variants, key=lambda item: (-len(item), item)))

    def __repr__(self) -> str:
        return (
            f"LayeredRedactor(version={self.version!r}, "
            f"known_secret_count={self.known_secret_count})"
        )

    @property
    def version(self) -> str:
        return f"r{_REDACTION_POLICY_VERSION}-e{self.__pseudonymizer.epoch}"

    @property
    def known_secret_count(self) -> int:
        return self.__known_secret_count

    def pseudonymize_path(self, value: str) -> str:
        """Return the shared policy's path pseudonym without exposing its key."""

        return sanitize_local_path(value, pseudonymizer=self.__pseudonymizer)

    def _replace_known_secrets(self, value: str, counts: dict[str, int]) -> str:
        for variant in self.__secret_variants:
            occurrences = value.count(variant)
            if occurrences:
                value = value.replace(variant, "[redacted:secret]")
                _increment(counts, "secret", occurrences)
        return value

    def _pseudonym(self, kind: str, value: str) -> str:
        return f"[{kind}:{self.__pseudonymizer.pseudonymize(kind, value)}]"

    def _ip_pseudonym(self, value: str) -> str:
        token = self.__pseudonymizer.pseudonymize("ip", value).replace("_", "-")
        return f"ip-{token}.invalid"

    def redact(self, value: str) -> RedactionResult:
        """Return bounded redacted text or fail without echoing the rejected value."""

        return self._redact(value, allowed_url_query_keys=frozenset())

    def redact_url(
        self,
        value: str,
        *,
        allowed_query_keys: frozenset[str] = frozenset(),
    ) -> RedactionResult:
        """Redact one URL while retaining only explicitly allowed safe query fields."""

        sanitize_url(value, allowed_query_keys=allowed_query_keys)
        return self._redact(value, allowed_url_query_keys=allowed_query_keys)

    def _redact(
        self,
        value: str,
        *,
        allowed_url_query_keys: frozenset[str],
    ) -> RedactionResult:
        text, removed_controls = _normalize_text(value)
        counts: dict[str, int] = {}
        if removed_controls:
            _increment(counts, "control", removed_controls)

        text = self._replace_known_secrets(text, counts)

        def replace_private_key(match: re.Match[str]) -> str:
            _increment(counts, "private_key")
            return "[redacted:private-key]"

        text = _PRIVATE_KEY_BLOCK.sub(replace_private_key, text)

        def replace_header(match: re.Match[str]) -> str:
            _increment(counts, "credential")
            return f"{match.group('name')}: [redacted:credential]"

        text = _CREDENTIAL_HEADER.sub(replace_header, text)

        def replace_email(match: re.Match[str]) -> str:
            _increment(counts, "email")
            return self._pseudonym("email", match.group(0))

        def replace_ip(match: re.Match[str]) -> str:
            candidate = match.group(0)
            unwrapped = candidate[1:-1] if candidate.startswith("[") else candidate
            try:
                normalized = str(ipaddress.ip_address(unwrapped))
            except ValueError:
                return candidate
            _increment(counts, "ip")
            return self._ip_pseudonym(normalized)

        def replace_phone(match: re.Match[str]) -> str:
            _increment(counts, "phone")
            normalized = "".join(character for character in match.group(0) if character.isdigit())
            return self._pseudonym("phone", normalized)

        def replace_path(match: re.Match[str]) -> str:
            _increment(counts, "path")
            candidate = match.group(0)
            token = self.pseudonymize_path(candidate)
            return f"/{token}" if candidate.startswith("/") else token

        def redact_url_component(component: str) -> str:
            component = _EMAIL.sub(replace_email, component)
            component = _BRACKETED_IPV6.sub(replace_ip, component)
            component = _IPV4.sub(replace_ip, component)
            component = _PHONE.sub(replace_phone, component)
            component = _UNC_PATH.sub(replace_path, component)
            component = _WINDOWS_PATH.sub(replace_path, component)
            return _POSIX_PATH.sub(replace_path, component)

        placeholder_prefix = "MHURLPLACEHOLDER"
        while placeholder_prefix in text:
            placeholder_prefix += "X"
        protected_urls: list[tuple[str, str]] = []

        def replace_url(match: re.Match[str]) -> str:
            if len(protected_urls) >= MAX_URLS_PER_TEXT:
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_URLS",
                    "redaction input contains too many URLs",
                )
            candidate = match.group(0)
            trimmed = candidate.rstrip(_TRAILING_URL_PUNCTUATION)
            trailing = candidate[len(trimmed) :]
            try:
                result = sanitize_url(
                    trimmed,
                    allowed_query_keys=allowed_url_query_keys,
                )
            except PrivacyError:
                _increment(counts, "url")
                return "[redacted:url]" + trailing
            removed = set(result.removed)
            parsed = urlsplit(result.value)
            url_host = parsed.hostname
            if url_host is None:  # pragma: no cover - sanitize_url guarantees this
                raise PrivacyError(
                    "MH_PRIVACY_REDACT_INVARIANT",
                    "sanitized URL lost its host",
                )
            try:
                normalized_ip = str(ipaddress.ip_address(url_host))
            except ValueError:
                safe_host = url_host
            else:
                _increment(counts, "ip")
                safe_host = self._ip_pseudonym(normalized_ip)
            if parsed.port is not None:
                safe_host = f"{safe_host}:{parsed.port}"
            path = redact_url_component(parsed.path)
            query_fields = [
                (key, redact_url_component(query_value))
                for key, query_value in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                    max_num_fields=100,
                )
            ]
            rebuilt = urlunsplit(
                (
                    parsed.scheme,
                    safe_host,
                    path,
                    urlencode(query_fields, doseq=True),
                    "",
                )
            )
            final = sanitize_url(
                rebuilt,
                allowed_query_keys=allowed_url_query_keys,
            )
            removed.update(final.removed)
            if final.value != trimmed:
                _increment(counts, "url")
            for category in removed:
                _increment(counts, f"url_{category}")
            placeholder = f"{placeholder_prefix}{len(protected_urls)}END"
            protected_urls.append((placeholder, final.value))
            return placeholder + trailing

        text = _URL.sub(replace_url, text)

        text = _EMAIL.sub(replace_email, text)
        text = _BRACKETED_IPV6.sub(replace_ip, text)
        text = _IPV4.sub(replace_ip, text)
        text = _PHONE.sub(replace_phone, text)
        text = _UNC_PATH.sub(replace_path, text)
        text = _WINDOWS_PATH.sub(replace_path, text)
        text = _POSIX_PATH.sub(replace_path, text)

        def replace_assignment(match: re.Match[str]) -> str:
            _increment(counts, "credential")
            return f"{match.group('name')}{match.group('separator')}[redacted:credential]"

        text = _CREDENTIAL_ASSIGNMENT.sub(replace_assignment, text)
        for placeholder, safe_url in protected_urls:
            text = text.replace(placeholder, safe_url)

        if len(text.encode("utf-8")) > MAX_REDACTED_TEXT_BYTES:
            raise PrivacyError(
                "MH_PRIVACY_REDACT_OUTPUT_LARGE",
                "redacted output exceeds the retained-text byte bound",
            )
        if not text and value:
            raise PrivacyError(
                "MH_PRIVACY_REDACT_EMPTY",
                "redaction removed all retained text",
            )
        if any(
            type(count) is not int or count <= 0 or not math.isfinite(count)
            for count in counts.values()
        ):
            raise PrivacyError(  # pragma: no cover - internal invariant
                "MH_PRIVACY_REDACT_INVARIANT",
                "redaction count invariant failed",
            )
        return RedactionResult(value=text, counts=counts)
