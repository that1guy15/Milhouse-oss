"""Installation-keyed pseudonyms and fingerprints for privacy-safe correlation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import unicodedata

from milhouse.core.errors import MilhouseValueError

PSEUDONYM_KEY_BYTES = 32
MAX_PSEUDONYM_INPUT_BYTES = 1_048_576
MAX_PSEUDONYM_KIND_BYTES = 32

_KIND_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_PSEUDONYM_DOMAIN = b"milhouse-pseudonym-v1\0"
_FINGERPRINT_DOMAIN = b"milhouse-fingerprint-v1\0"
_KEY_ID_DOMAIN = b"milhouse-pseudonym-key-id-v1\0"


class PrivacyError(MilhouseValueError):
    """A stable privacy failure whose message never contains rejected input."""


def _base32(value: bytes) -> str:
    return base64.b32encode(value).decode("ascii").lower().rstrip("=")


def _normalize_text(value: str) -> bytes:
    if type(value) is not str:
        raise PrivacyError("MH_PRIVACY_INPUT_TYPE", "input must be text")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError("MH_PRIVACY_UNICODE", "input contains unsupported Unicode")
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    encoded = normalized.encode("utf-8")
    if not encoded:
        raise PrivacyError("MH_PRIVACY_INPUT_EMPTY", "input must not be empty")
    if len(encoded) > MAX_PSEUDONYM_INPUT_BYTES:
        raise PrivacyError("MH_PRIVACY_INPUT_LARGE", "input exceeds the privacy byte bound")
    return encoded


def validate_pseudonym_kind(kind: str) -> str:
    """Return one code-owned kind accepted by every pseudonym operation."""

    if type(kind) is not str or _KIND_PATTERN.fullmatch(kind) is None:
        raise PrivacyError("MH_PRIVACY_KIND", "pseudonym kind is invalid")
    encoded = kind.encode("ascii")
    if len(encoded) > MAX_PSEUDONYM_KIND_BYTES:  # pragma: no cover - regex bounds this
        raise PrivacyError("MH_PRIVACY_KIND", "pseudonym kind is invalid")
    return kind


def _validate_kind(kind: str) -> bytes:
    return validate_pseudonym_kind(kind).encode("ascii")


def validate_pseudonym_epoch(epoch: int) -> int:
    """Return one valid persisted pseudonym epoch without coercing booleans or strings."""

    if type(epoch) is not int or not 1 <= epoch <= 2_147_483_647:
        raise PrivacyError("MH_PRIVACY_EPOCH", "pseudonym epoch is invalid")
    return epoch


class Pseudonymizer:
    """Derive deterministic, domain-separated tokens without exposing the key or value."""

    __slots__ = ("__epoch", "__key")

    def __init__(self, key: bytes, epoch: int = 1) -> None:
        if type(key) is not bytes or len(key) != PSEUDONYM_KEY_BYTES:
            raise PrivacyError(
                "MH_PRIVACY_KEY_LENGTH",
                f"pseudonym key must contain exactly {PSEUDONYM_KEY_BYTES} bytes",
            )
        self.__key = bytes(key)
        self.__epoch = validate_pseudonym_epoch(epoch)

    def __repr__(self) -> str:
        return f"Pseudonymizer(epoch={self.epoch})"

    @property
    def epoch(self) -> int:
        return self.__epoch

    @property
    def key_id(self) -> str:
        digest = hashlib.sha256(_KEY_ID_DOMAIN + self.__key).hexdigest()[:16]
        return f"mh_pk1_{digest}"

    def _digest(self, domain: bytes, kind: str, value: str) -> bytes:
        kind_bytes = _validate_kind(kind)
        value_bytes = _normalize_text(value)
        epoch_bytes = self.epoch.to_bytes(4, "big", signed=False)
        message = domain + epoch_bytes + kind_bytes + b"\0" + value_bytes
        return hmac.digest(self.__key, message, "sha256")

    def pseudonymize(self, kind: str, value: str) -> str:
        """Return a 128-bit keyed correlation token for one normalized string."""

        digest = self._digest(_PSEUDONYM_DOMAIN, kind, value)[:16]
        return f"mh_ps1_e{self.epoch}_{kind}_{_base32(digest)}"

    def fingerprint(self, kind: str, value: str) -> str:
        """Return a full keyed digest for fail-closed rejection and audit correlation."""

        digest = self._digest(_FINGERPRINT_DOMAIN, kind, value)
        return f"mh_fp1_e{self.epoch}_{kind}_{_base32(digest)}"


__all__ = [
    "MAX_PSEUDONYM_INPUT_BYTES",
    "MAX_PSEUDONYM_KIND_BYTES",
    "PSEUDONYM_KEY_BYTES",
    "PrivacyError",
    "Pseudonymizer",
    "validate_pseudonym_epoch",
    "validate_pseudonym_kind",
]
