"""Offline tests for the installation-ownership guard (fake client; no ClickHouse, no network)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from _storage_fakes import FakeClickHouseClient

from milhouse.storage import StorageError, migrate
from milhouse.storage.ownership import claim, read_owner, require_owner

_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=UTC)
_LATER = datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC)
_DB = "milhouse"
_A = "mh_in1_" + "a" * 32
_B = "mh_in1_" + "b" * 32


def _migrated() -> FakeClickHouseClient:
    # Migration 0006 provisions the ``_installation`` table; a claim only ever happens post-migrate.
    fake = FakeClickHouseClient()
    migrate(fake, _DB, now=_NOW, milhouse_version="test")
    return fake


def test_read_owner_on_an_unmigrated_destination_is_none() -> None:
    assert (
        read_owner(FakeClickHouseClient(), _DB) is None
    )  # no database, no _installation, no raise


def test_read_owner_on_a_migrated_but_unclaimed_destination_is_none() -> None:
    assert read_owner(_migrated(), _DB) is None  # table exists but holds no claim


def test_claim_stamps_an_unclaimed_destination() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    assert read_owner(fake, _DB) == _A


def test_claim_by_the_same_installation_is_a_noop() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    claim(fake, _DB, installation_id=_A, now=_LATER, milhouse_version="test")  # no raise
    assert read_owner(fake, _DB) == _A


def test_claim_by_a_different_installation_fails_closed() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    with pytest.raises(StorageError) as captured:
        claim(fake, _DB, installation_id=_B, now=_LATER, milhouse_version="test")
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"
    assert read_owner(fake, _DB) == _A  # the refused claim did not change the owner


def test_reclaim_supersedes_a_prior_owner() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    claim(fake, _DB, installation_id=_B, now=_LATER, milhouse_version="test", reclaim=True)
    assert read_owner(fake, _DB) == _B  # the newest claim supersedes


def test_require_owner_passes_for_the_owner() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    assert require_owner(fake, _DB, installation_id=_A) is None


def test_require_owner_fails_closed_for_a_different_installation() -> None:
    fake = _migrated()
    claim(fake, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    with pytest.raises(StorageError) as captured:
        require_owner(fake, _DB, installation_id=_B)
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"


def test_require_owner_on_an_unclaimed_destination_fails_closed() -> None:
    with pytest.raises(StorageError) as captured:
        require_owner(_migrated(), _DB, installation_id=_A)
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"
    assert "migrate" in captured.value.message  # the "run `storage migrate` first" guidance


def test_claim_rejects_a_bad_installation_id_before_writing() -> None:
    fake = _migrated()
    with pytest.raises(StorageError) as captured:
        claim(fake, _DB, installation_id="bad; DROP", now=_NOW, milhouse_version="test")
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"
    assert read_owner(fake, _DB) is None  # nothing was written


def test_invalid_database_identifier_is_rejected() -> None:
    with pytest.raises(StorageError) as captured:
        read_owner(FakeClickHouseClient(), "bad name; DROP")
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"


def test_ownership_is_per_destination() -> None:
    # Two different fakes model two different ClickHouse destinations; each is claimable on its own
    # by a different installation, the "installation id per client instance" the guard needs.
    destination_1 = _migrated()
    destination_2 = _migrated()
    claim(destination_1, _DB, installation_id=_A, now=_NOW, milhouse_version="test")
    claim(destination_2, _DB, installation_id=_B, now=_NOW, milhouse_version="test")
    assert read_owner(destination_1, _DB) == _A
    assert read_owner(destination_2, _DB) == _B


def test_claim_rejects_a_naive_now() -> None:
    fake = _migrated()
    with pytest.raises(StorageError) as captured:
        claim(
            fake, _DB, installation_id=_A, now=datetime(2026, 8, 3, 12, 0, 0), milhouse_version="t"
        )
    assert captured.value.code == "MH_STORAGE_OWNERSHIP"
