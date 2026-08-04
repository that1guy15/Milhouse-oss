"""Opt-in live G04a smoke against a real loopback ClickHouse. NOT part of Required CI.

Runs only when ``MILHOUSE_LIVE_CLICKHOUSE`` is set (and a loopback server is reachable via the
``MILHOUSE_CLICKHOUSE_*`` env vars). It exercises the live G04a exit criteria the offline suite
cannot prove: anonymous access fails, authenticated access succeeds, a fresh deployment migrates to
the full schema, migration status works, and checksum enforcement refuses a tampered ledger.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from milhouse.config._models import StorageClickHouseConfig
from milhouse.config.secrets import SecretEnvironment
from milhouse.storage import StorageError, build_client, migrate, plan, status

pytestmark = pytest.mark.live

_ENABLED = os.environ.get("MILHOUSE_LIVE_CLICKHOUSE")
_SMOKE_DB = "milhouse_live_smoke"
_requires_live = pytest.mark.skipif(
    not _ENABLED,
    reason="set MILHOUSE_LIVE_CLICKHOUSE=1 and MILHOUSE_CLICKHOUSE_* against a loopback server",
)


def _config(
    *, user_env: str = "MILHOUSE_CLICKHOUSE_USER", pass_env: str = "MILHOUSE_CLICKHOUSE_PASSWORD"
) -> StorageClickHouseConfig:
    return StorageClickHouseConfig(
        enabled=True,
        url_env="MILHOUSE_CLICKHOUSE_URL",
        username_env=user_env,
        password_env=pass_env,
        database=_SMOKE_DB,
        connect_timeout_seconds=5,
    )


def _secrets(overrides: dict[str, str] | None = None) -> SecretEnvironment:
    values = {
        key: os.environ[key]
        for key in (
            "MILHOUSE_CLICKHOUSE_URL",
            "MILHOUSE_CLICKHOUSE_USER",
            "MILHOUSE_CLICKHOUSE_PASSWORD",
        )
        if key in os.environ
    }
    values.update(overrides or {})
    return SecretEnvironment(values, {})


@_requires_live
def test_live_fresh_migrate_status_idempotent_and_checksum_enforcement() -> None:
    client = build_client(_config(), _secrets())
    try:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")

        assert plan(client, _SMOKE_DB).current_version == 0  # fresh deployment

        result = migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert result.current_version == 4  # migrated to the full schema
        assert status(client, _SMOKE_DB).current_version == 4  # status reports it

        again = migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert again.applied_now == ()  # idempotent

        client.command(
            f"ALTER TABLE {_SMOKE_DB}._migrations UPDATE checksum = 'deadbeef' "
            "WHERE version = 1 SETTINGS mutations_sync = 1"
        )
        with pytest.raises(StorageError) as captured:
            migrate(client, _SMOKE_DB, now=datetime.now(UTC), milhouse_version="live-smoke")
        assert captured.value.code == "MH_STORAGE_MIGRATION"
    finally:
        client.command(f"DROP DATABASE IF EXISTS {_SMOKE_DB}")
        client.close()


@_requires_live
def test_live_default_empty_password_account_is_denied() -> None:
    # The built-in `default` account with an EMPTY password is the anonymous/unauthenticated vector
    # G04a must reject and the whole compose/users.d hardening exists to lock. A hardened deployment
    # rejects it; an open server (missing the users.d lock) would let this connect — exactly the
    # regression this case exists to catch.
    client = build_client(
        _config(user_env="MILHOUSE_LIVE_DEFAULT_USER", pass_env="MILHOUSE_LIVE_DEFAULT_PASSWORD"),
        _secrets({"MILHOUSE_LIVE_DEFAULT_USER": "default", "MILHOUSE_LIVE_DEFAULT_PASSWORD": ""}),
    )
    with pytest.raises(StorageError) as captured:
        client.query("SELECT 1")
    assert captured.value.code == "MH_STORAGE_CLIENT"
    client.close()
