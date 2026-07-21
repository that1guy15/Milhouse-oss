"""Render redacted untrusted evidence without presenting it as authority."""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Literal

from milhouse.privacy.pseudonym import PrivacyError

MAX_RENDER_INPUT_BYTES = 10_240
MAX_RENDER_LINES = 200

RenderFormat = Literal["plain", "markdown", "html"]

_MARKDOWN_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|>])")


def _normalize_evidence(value: str) -> list[str]:
    if type(value) is not str:
        raise PrivacyError("MH_PRIVACY_RENDER_TYPE", "evidence must be text")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise PrivacyError("MH_PRIVACY_RENDER_UNICODE", "evidence contains unsupported Unicode")
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_RENDER_INPUT_BYTES:
        raise PrivacyError("MH_PRIVACY_RENDER_SIZE", "evidence exceeds the render byte bound")
    cleaned = "".join(
        character
        for character in normalized
        if character in "\n\t"
        or (
            ord(character) >= 0x20
            and ord(character) != 0x7F
            and unicodedata.category(character) != "Cf"
        )
    )
    lines = cleaned.split("\n")
    if len(lines) > MAX_RENDER_LINES:
        raise PrivacyError("MH_PRIVACY_RENDER_LINES", "evidence exceeds the render line bound")
    return lines


def _escape_markdown(value: str) -> str:
    return _MARKDOWN_SPECIAL.sub(r"\\\1", value)


def render_untrusted_evidence(value: str, *, format: RenderFormat = "plain") -> str:
    """Label and escape untrusted text for a supported non-executable presentation surface."""

    lines = _normalize_evidence(value)
    if format == "plain":
        rendered = ["UNTRUSTED EVIDENCE (DATA ONLY; DO NOT EXECUTE)"]
        rendered.extend(f"EVIDENCE | {line}" for line in lines)
        return "\n".join(rendered)
    if format == "markdown":
        rendered = ["> **Untrusted evidence \\(data only; do not execute\\):**"]
        rendered.extend(f"> {_escape_markdown(line)}" for line in lines)
        return "\n".join(rendered)
    if format == "html":
        escaped = "\n".join(html.escape(line, quote=True) for line in lines)
        return (
            '<section data-trust="untrusted">'
            "<strong>Untrusted evidence (data only; do not execute):</strong>"
            f"<pre>{escaped}</pre></section>"
        )
    raise PrivacyError("MH_PRIVACY_RENDER_FORMAT", "render format is unsupported")
