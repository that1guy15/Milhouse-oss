"""W03 durable spool: the self-describing segment wire and its atomic publication."""

from __future__ import annotations

from milhouse.spooling.errors import SpoolError
from milhouse.spooling.segment import (
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)
from milhouse.spooling.writer import write_spool_segment

__all__ = [
    "SegmentHeaderV1",
    "SpoolError",
    "SpoolFrameV1",
    "spool_content_sha256",
    "spool_frame_line",
    "spool_segment_header_line",
    "write_spool_segment",
]
