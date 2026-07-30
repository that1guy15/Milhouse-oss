"""W03 durable spool: the self-describing segment wire and its atomic publication."""

from __future__ import annotations

from milhouse.spooling.commit import DurableSpool
from milhouse.spooling.errors import SpoolError
from milhouse.spooling.exporter import Exporter, ExporterAttempt, deliver_segment
from milhouse.spooling.ledger import ExporterDelivery, SegmentRecord
from milhouse.spooling.reader import (
    ParsedSegment,
    parse_segment_bytes,
    read_trusted_segment,
    read_untrusted_segment,
)
from milhouse.spooling.reconcile import (
    OrphanRegistration,
    QuarantinedFile,
    ReconciliationReport,
    SegmentAnomaly,
    SpoolReconciler,
)
from milhouse.spooling.replay import ReplayReport, replay_segments
from milhouse.spooling.segment import (
    SegmentHeaderV1,
    SpoolFrameV1,
    spool_content_sha256,
    spool_frame_line,
    spool_segment_header_line,
)
from milhouse.spooling.writer import (
    build_segment_bytes,
    publish_segment_bytes,
    write_spool_segment,
)

__all__ = [
    "DurableSpool",
    "Exporter",
    "ExporterAttempt",
    "ExporterDelivery",
    "OrphanRegistration",
    "ParsedSegment",
    "QuarantinedFile",
    "ReconciliationReport",
    "ReplayReport",
    "SegmentAnomaly",
    "SegmentHeaderV1",
    "SegmentRecord",
    "SpoolError",
    "SpoolFrameV1",
    "SpoolReconciler",
    "build_segment_bytes",
    "deliver_segment",
    "parse_segment_bytes",
    "publish_segment_bytes",
    "read_trusted_segment",
    "read_untrusted_segment",
    "replay_segments",
    "spool_content_sha256",
    "spool_frame_line",
    "spool_segment_header_line",
    "write_spool_segment",
]
