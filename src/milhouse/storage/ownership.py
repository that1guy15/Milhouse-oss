"""Installation-ownership guard for the ClickHouse analytical store (W04, plan section 4.5).

Milhouse's single-writer correctness rests on the local control-plane commit barrier
(:class:`~milhouse.state.GlobalCommitBarrier`), which serializes exactly ONE installation's
ClickHouse writers. That barrier is a machine-local lock: it cannot fence a SECOND installation --
a different state root, clone, or host -- pointed at the SAME ClickHouse. Two such installs would
each hold the single-writer lock while silently comingling and corrupting each other's data. The
supported model is therefore "one ClickHouse per installation", and this module makes it an
enforced, fail-closed invariant: a second installation is REFUSED rather than allowed to corrupt
the store.

Migration ``0006`` provisions the single-owner control table ``{database}._installation`` -- one
logical row at ``id = 1`` under ``ReplacingMergeTree(claimed_at)`` so the newest claim supersedes on
merge -- and this API reads and stamps it over the same small
:class:`~milhouse.storage.client.ClickHouseClient` seam the runner uses, so its logic is fully
unit-testable against a fake client with no network:

* :func:`read_owner` -- the current owning installation id, or ``None`` when the destination is
  unclaimed (no database or ``_installation`` table, or an empty table). It never raises on an
  unmigrated destination, mirroring the runner's existence-guarded ledger read, so a fresh
  deployment can be probed safely.
* :func:`claim` -- stamp the local installation as owner (``storage migrate``). An unclaimed
  destination is stamped; an already-owned destination is a no-op for the SAME id; a DIFFERENT id
  fails closed ``MH_STORAGE_OWNERSHIP`` unless ``reclaim`` is set, which inserts a superseding claim
  to deliberately re-point an installation at a new destination.
* :func:`require_owner` -- the read barrier every write/restore op takes
  (``storage export``/``backup``/``restore``). A DIFFERENT owner OR an unclaimed destination fails
  closed ``MH_STORAGE_OWNERSHIP``.

Every failure is a fixed, privacy-safe :class:`~milhouse.storage.errors.StorageError` carrying the
``MH_STORAGE_OWNERSHIP`` code and no secret, credential, driver payload, or machine-local path. The
owning installation id is the non-secret ``mh_in1_`` record-identity id (plan section 4.2); it is
validated as a bounded token before it is written, because -- like a database name -- it is a
structural literal in the single-row claim statement and cannot be server-side parameter-bound.
"""

from __future__ import annotations

import re
from datetime import datetime

from milhouse.core.clock import TimeError, truncate_to_milliseconds
from milhouse.storage._identifiers import require_identifier
from milhouse.storage.client import ClickHouseClient
from milhouse.storage.errors import StorageError

_OWNERSHIP_CODE = "MH_STORAGE_OWNERSHIP"
_INSTALLATION_TABLE = "_installation"
#: The single logical owner row's fixed primary key; ReplacingMergeTree keeps only the newest claim.
_OWNER_ROW_ID = 1
#: The non-secret ``mh_in1_`` record-identity shape (plan section 4.2): the prefix plus a uuid4 hex
#: payload. Validated before interpolation so only this bounded token can ever reach the claim
#: statement -- a malformed or hostile id fails closed rather than forming part of a statement.
_INSTALLATION_ID = re.compile(r"mh_in1_[0-9a-f]{32}", flags=re.ASCII)

_OTHER_OWNER_MESSAGE = (
    "this ClickHouse destination is owned by another installation; "
    "use --reclaim on migrate to take ownership"
)
_UNCLAIMED_MESSAGE = "the ClickHouse destination is unclaimed; run `storage migrate` first"


def _validate_database(database: object) -> str:
    return require_identifier(
        database,
        code=_OWNERSHIP_CODE,
        message="a bounded ClickHouse database identifier is required",
    )


def _validate_installation_id(installation_id: object) -> str:
    if type(installation_id) is not str or _INSTALLATION_ID.fullmatch(installation_id) is None:
        raise StorageError(_OWNERSHIP_CODE, "a valid installation id is required")
    return installation_id


def _timestamp(now: datetime) -> str:
    try:
        normalized = truncate_to_milliseconds(now)
    except (TimeError, OverflowError, AttributeError, TypeError):
        raise StorageError(
            _OWNERSHIP_CODE, "the ownership timestamp must be an aware in-range UTC instant"
        ) from None
    return normalized.strftime("%Y-%m-%d %H:%M:%S.") + f"{normalized.microsecond // 1000:03d}"


def _database_exists(client: ClickHouseClient, database: str) -> bool:
    rows = client.query(f"SELECT count() FROM system.databases WHERE name = '{database}'")
    return bool(rows) and int(rows[0][0]) > 0


def _table_exists(client: ClickHouseClient, database: str, table: str) -> bool:
    rows = client.query(
        f"SELECT count() FROM system.tables WHERE database = '{database}' AND name = '{table}'"
    )
    return bool(rows) and int(rows[0][0]) > 0


def read_owner(client: ClickHouseClient, database: str) -> str | None:
    """Return the installation id that owns ``database``, or ``None`` if it is unclaimed.

    Returns ``None`` -- never raises -- when the database or the ``_installation`` table does not
    exist yet (an unmigrated/absent destination) or the table holds no claim, mirroring the runner's
    existence-guarded ledger read. Otherwise it reads the single owner row through ``FINAL`` so the
    newest claim is observed even before a ReplacingMergeTree merge has run. The database name is
    validated as a bounded identifier (it is structural and cannot be parameter-bound); no value is
    interpolated by this read.
    """

    database = _validate_database(database)
    if not _database_exists(client, database) or not _table_exists(
        client, database, _INSTALLATION_TABLE
    ):
        return None
    rows = client.query(
        f"SELECT installation_id FROM {database}.{_INSTALLATION_TABLE} FINAL "
        f"WHERE id = {_OWNER_ROW_ID}"
    )
    if not rows:
        return None
    owner = str(rows[0][0])
    return owner or None


def claim(
    client: ClickHouseClient,
    database: str,
    *,
    installation_id: str,
    now: datetime,
    milhouse_version: str,
    reclaim: bool = False,
) -> None:
    """Stamp ``installation_id`` as the owner of ``database``; fail closed on a conflicting owner.

    Called by ``storage migrate`` AFTER the migrations apply, so the ``_installation`` table exists.
    An unclaimed destination is stamped with the claim row. An already-owned destination is a no-op
    when the recorded owner is the SAME installation. A DIFFERENT recorded owner fails closed
    ``MH_STORAGE_OWNERSHIP`` UNLESS ``reclaim`` is set (a re-point to a new host), in which case a
    superseding claim row is inserted and the ReplacingMergeTree keeps it as the current owner.

    The single-row claim is written with :meth:`~milhouse.storage.client.ClickHouseClient.command`
    exactly as the migration ledger writes its rows; the ``installation_id`` is validated as a
    bounded ``mh_in1_`` token first, so only that token -- not untrusted content -- is interpolated.
    """

    database = _validate_database(database)
    installation_id = _validate_installation_id(installation_id)
    current = read_owner(client, database)
    if current is not None:
        if current == installation_id:
            return  # already owned by this installation; nothing to stamp
        if not reclaim:
            raise StorageError(_OWNERSHIP_CODE, _OTHER_OWNER_MESSAGE)
    stamp = _timestamp(now)
    columns = "id, installation_id, claimed_at, milhouse_version"
    values = f"({_OWNER_ROW_ID}, '{installation_id}', '{stamp}', '{milhouse_version}')"
    client.command(f"INSERT INTO {database}.{_INSTALLATION_TABLE} ({columns}) VALUES {values}")


def require_owner(client: ClickHouseClient, database: str, *, installation_id: str) -> None:
    """Fail closed unless ``database`` is owned by the local ``installation_id``.

    The read barrier ``storage export``/``backup``/``restore`` take before touching the store: a
    DIFFERENT owner or an UNCLAIMED destination raises ``MH_STORAGE_OWNERSHIP`` (with the
    "use --reclaim on migrate" or "run ``storage migrate`` first" guidance), and returns ``None``
    only when the local installation owns it. This is what refuses a second installation pointed at
    another installation's ClickHouse -- including a restore of another installation's backup, whose
    restored ``_installation`` row names that other owner.
    """

    database = _validate_database(database)
    installation_id = _validate_installation_id(installation_id)
    owner = read_owner(client, database)
    if owner is None:
        raise StorageError(_OWNERSHIP_CODE, _UNCLAIMED_MESSAGE)
    if owner != installation_id:
        raise StorageError(_OWNERSHIP_CODE, _OTHER_OWNER_MESSAGE)


__all__ = ["claim", "read_owner", "require_owner"]
