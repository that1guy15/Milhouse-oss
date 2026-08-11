"""Stable, privacy-safe error type for the ClickHouse storage layer (W04)."""

from __future__ import annotations

from milhouse.core.errors import MilhouseValueError


class StorageError(MilhouseValueError):
    """A fail-closed storage failure carrying a fixed ``MH_STORAGE_*`` code.

    Codes: ``MH_STORAGE_MIGRATION`` (migration ledger/checksum/ordering), ``MH_STORAGE_CLIENT``
    (client construction or a driver fault), ``MH_STORAGE_CONFIG`` (missing/invalid storage config
    or credentials), ``MH_STORAGE_BACKUP`` (native-backup snapshot or statement building), and
    ``MH_STORAGE_RESTORE`` (a restore-round-trip verification, cross-store reconciliation, or
    restore statement building). The message never carries a secret, a credential, a raw driver
    payload, or a machine-local path.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code, message)
