"""Self-describing spool segment wire: header, frames, and the ordered-frame digest (W03 slice 2).

Per ADR 0004 and plan section 4.3 a durable segment is one self-describing file: the first JSONL
line is a ``SegmentHeaderV1`` and the remaining lines are ordered ``SpoolFrameV1`` records, each
carrying the complete redacted ``RecordEnvelopeV1``. The header records the frame/schema versions,
batch id,
configuration-generation digest, scope/target, privacy and retention class, required exporter ids,
expected record count, and the SHA-256 digest of the ordered frame bytes. Lines are bounded
``CanonicalJSONV1``, so segment bytes are deterministic across processes and platforms. This module
owns only the wire and the digest; the atomic write and the SQLite ledger live in sibling modules.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import NoReturn

from milhouse.core.canonical import MAX_CANONICAL_INT, canonical_json_bytes
from milhouse.domain.identity import ScopeV1
from milhouse.domain.records import PrivacyClassV1, RecordEnvelopeV1
from milhouse.spooling.errors import SpoolError

_LF = b"\n"
SCHEMA_VERSION = 1
FRAME_VERSION = 1
MAX_HEADER_LINE_BYTES = 8_192
MAX_FRAME_LINE_BYTES = 262_144 + 1_024  # a canonical record plus the small frame envelope
MAX_RETENTION_DAYS = 3_650  # matches the config `[retention]` ceiling

_BATCH_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", flags=re.ASCII)
_EXPORTER_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", flags=re.ASCII)
_TARGET_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", flags=re.ASCII)
_SHA256_HEX_PATTERN = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)
_SCOPES = ("installation", "target")
_PRIVACY_CLASSES = ("public", "internal", "sensitive", "restricted")


def _fail(code: str, message: str) -> NoReturn:
    raise SpoolError(code, message)


def _validate_batch_id(value: object) -> None:
    if type(value) is not str or _BATCH_ID_PATTERN.fullmatch(value) is None:
        _fail("MH_SPOOL_BATCH_ID", "a bounded safe batch id is required")


def _validate_positive_sequence(value: object) -> None:
    if type(value) is not int or not 0 < value <= MAX_CANONICAL_INT:
        _fail("MH_SPOOL_SEQUENCE", "a positive signed-64 sequence is required")


@dataclass(frozen=True, slots=True)
class SpoolFrameV1:
    """One ordered spool frame binding a batch sequence to a finalized record envelope."""

    batch_id: str
    sequence: int
    record: RecordEnvelopeV1

    def __post_init__(self) -> None:
        _validate_batch_id(self.batch_id)
        _validate_positive_sequence(self.sequence)
        if not isinstance(self.record, RecordEnvelopeV1):
            _fail("MH_SPOOL_RECORD", "a finalized record envelope is required")


@dataclass(frozen=True, slots=True)
class SegmentHeaderV1:
    """The immutable self-describing header opening one durable spool segment."""

    batch_id: str
    config_generation: str
    scope: ScopeV1
    target_id: str | None
    privacy_class: PrivacyClassV1
    retention_days: int
    required_exporters: tuple[str, ...]
    record_count: int
    content_sha256: str

    def __post_init__(self) -> None:
        _validate_batch_id(self.batch_id)
        if (
            type(self.config_generation) is not str
            or _SHA256_HEX_PATTERN.fullmatch(self.config_generation) is None
        ):
            _fail(
                "MH_SPOOL_CONFIG_GENERATION", "a 64-hex configuration-generation digest is required"
            )
        if self.scope not in _SCOPES:
            _fail("MH_SPOOL_SCOPE", "an installation or target scope is required")
        if self.scope == "target":
            if (
                type(self.target_id) is not str
                or _TARGET_ID_PATTERN.fullmatch(self.target_id) is None
            ):
                _fail("MH_SPOOL_TARGET", "target scope requires a bounded target id")
        elif self.target_id is not None:
            _fail("MH_SPOOL_TARGET", "installation scope forbids a target id")
        if self.privacy_class not in _PRIVACY_CLASSES:
            _fail("MH_SPOOL_PRIVACY", "a valid privacy class is required")
        if (
            type(self.retention_days) is not int
            or not 0 < self.retention_days <= MAX_RETENTION_DAYS
        ):
            _fail("MH_SPOOL_RETENTION", "a bounded positive retention is required")
        if type(self.required_exporters) is not tuple:
            _fail("MH_SPOOL_EXPORTERS", "required exporters must be a tuple")
        for exporter in self.required_exporters:
            if type(exporter) is not str or _EXPORTER_ID_PATTERN.fullmatch(exporter) is None:
                _fail("MH_SPOOL_EXPORTERS", "each exporter id must be bounded safe text")
        if list(self.required_exporters) != sorted(set(self.required_exporters)):
            _fail("MH_SPOOL_EXPORTERS", "required exporters must be sorted and unique")
        if type(self.record_count) is not int or not 0 <= self.record_count <= MAX_CANONICAL_INT:
            _fail("MH_SPOOL_COUNT", "a bounded record count is required")
        if (
            type(self.content_sha256) is not str
            or _SHA256_HEX_PATTERN.fullmatch(self.content_sha256) is None
        ):
            _fail("MH_SPOOL_DIGEST", "a lowercase hex sha-256 digest is required")


def spool_frame_line(frame: SpoolFrameV1) -> bytes:
    """Project one frame to its bounded canonical JSONL bytes including the trailing line feed."""

    if not isinstance(frame, SpoolFrameV1):
        _fail("MH_SPOOL_FRAME", "a spool frame is required")
    payload = {
        "batch_id": frame.batch_id,
        "frame_version": FRAME_VERSION,
        "record": frame.record.model_dump(mode="python", exclude_none=True),
        "record_id": frame.record.record_id,
        "sequence": frame.sequence,
    }
    return canonical_json_bytes(payload, max_bytes=MAX_FRAME_LINE_BYTES - len(_LF)) + _LF


def spool_segment_header_line(header: SegmentHeaderV1) -> bytes:
    """Project the segment header to its bounded canonical JSONL bytes including the line feed."""

    if not isinstance(header, SegmentHeaderV1):
        _fail("MH_SPOOL_HEADER", "a segment header is required")
    payload = {
        "batch_id": header.batch_id,
        "config_generation": header.config_generation,
        "content_sha256": header.content_sha256,
        "frame_version": FRAME_VERSION,
        "privacy_class": header.privacy_class,
        "record_count": header.record_count,
        "required_exporters": list(header.required_exporters),
        "retention_days": header.retention_days,
        "schema": SCHEMA_VERSION,
        "scope": header.scope,
        "target_id": header.target_id,
    }
    return canonical_json_bytes(payload, max_bytes=MAX_HEADER_LINE_BYTES - len(_LF)) + _LF


def spool_content_sha256(frame_lines: Iterable[bytes]) -> str:
    """Return the SHA-256 over the ordered frame-line bytes, including their line feeds.

    The header carries this digest, so the digest covers only the frame bytes and not the header. A
    hostile ``__iter__``/``__next__`` or a non-bytes element fails closed with a fixed
    ``MH_SPOOL_DIGEST`` raised outside the handler.
    """

    digest = hashlib.sha256()
    failed = False
    try:
        for line in frame_lines:
            if type(line) is not bytes:
                failed = True
                break
            digest.update(line)
    except Exception:
        failed = True
    if failed:
        _fail("MH_SPOOL_DIGEST", "the frame lines are invalid")
    return digest.hexdigest()
