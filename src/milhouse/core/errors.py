"""Stable, value-safe error primitives for internal Milhouse boundaries."""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_ERROR_CODE_BYTES = 128
MAX_ERROR_MESSAGE_BYTES = 2_048
UNEXPECTED_ERROR_CODE = "MH_INTERNAL_UNEXPECTED"

_ERROR_CODE_PATTERN = re.compile(
    r"(?:MH_[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*|[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)",
    flags=re.ASCII,
)


def _validate_error_code(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_ERROR_CODE_BYTES
        or _ERROR_CODE_PATTERN.fullmatch(value) is None
    ):
        raise ValueError("stable error code is invalid")
    return value


def _validate_error_message(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError("stable error message is invalid")
    if (
        any(
            ord(character) < 0x20 or ord(character) == 0x7F or 0xD800 <= ord(character) <= 0xDFFF
            for character in value
        )
        or len(value.encode("utf-8")) > MAX_ERROR_MESSAGE_BYTES
    ):
        raise ValueError("stable error message is invalid")
    return value


class MilhouseError(Exception):
    """Base for expected failures with bounded developer-defined code and text."""

    __slots__ = ("_code", "_message")

    def __init__(self, code: str, message: str) -> None:
        validated_code = _validate_error_code(code)
        validated_message = _validate_error_message(message)
        self._code = validated_code
        self._message = validated_message
        super().__init__(self._format_exception(validated_code, validated_message))

    @staticmethod
    def _format_exception(code: str, message: str) -> str:
        return f"{code}: {message}"

    @property
    def code(self) -> str:
        """Return the stable machine code without inspecting rejected input."""

        return self._code

    @property
    def message(self) -> str:
        """Return bounded developer-defined human text."""

        return self._message

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class MilhouseValueError(MilhouseError, ValueError):
    """Stable Milhouse error that preserves ``ValueError`` compatibility."""


@dataclass(frozen=True, slots=True, init=False)
class NormalizedError:
    """Privacy-safe error metadata suitable for structured operational events."""

    code: str
    expected: bool

    def __init__(self) -> None:
        raise TypeError("NormalizedError values are created by normalize_error")

    @classmethod
    def _create(cls, *, code: str, expected: bool) -> NormalizedError:
        if type(expected) is not bool:
            raise ValueError("normalized error expectation is invalid")
        instance = object.__new__(cls)
        object.__setattr__(instance, "code", _validate_error_code(code))
        object.__setattr__(instance, "expected", expected)
        return instance


def _unexpected_error() -> NormalizedError:
    return NormalizedError._create(code=UNEXPECTED_ERROR_CODE, expected=False)


def normalize_error(error: BaseException) -> NormalizedError:
    """Return code-only metadata without rendering or traversing an exception graph."""

    if not isinstance(error, MilhouseError):
        return _unexpected_error()
    try:
        code = object.__getattribute__(error, "_code")
        validated_code = _validate_error_code(code)
    except (AttributeError, TypeError, UnicodeError, ValueError):
        return _unexpected_error()
    return NormalizedError._create(code=validated_code, expected=True)


__all__ = [
    "MAX_ERROR_CODE_BYTES",
    "MAX_ERROR_MESSAGE_BYTES",
    "UNEXPECTED_ERROR_CODE",
    "MilhouseError",
    "MilhouseValueError",
    "NormalizedError",
    "normalize_error",
]
