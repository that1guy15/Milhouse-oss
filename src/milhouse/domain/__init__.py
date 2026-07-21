"""Canonical Milhouse domain contracts."""

from milhouse.domain.identity import (
    RecordDedupeV1,
    RecordIdentityV1,
    derive_content_hash,
    derive_dedupe_key,
    derive_record_id,
)

__all__ = [
    "RecordDedupeV1",
    "RecordIdentityV1",
    "derive_content_hash",
    "derive_dedupe_key",
    "derive_record_id",
]
