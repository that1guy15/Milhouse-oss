# Reference ClickHouse (local development)

A loopback-only, authenticated ClickHouse for developing against Milhouse's analytical store (W04,
plan section 4.5, ADR 0005). **Not a production deployment**, and **not started by `milhouse init`** —
ClickHouse is optional and the durable spool is the collection authority.

## Version

Pinned to the **ClickHouse 26.3 LTS** reference line by exact image digest
(`clickhouse/clickhouse-server:26.3@sha256:422be85a…`). The **25.8 LTS** line is the
compatibility-test target while it receives security updates.

## Start it

```console
$ cp .env.example .env      # then edit .env and set a non-empty MILHOUSE_CLICKHOUSE_APP_PASSWORD
$ docker compose --env-file .env up -d
```

- Every port is bound to `127.0.0.1` only — the server is never reachable off the host.
- The built-in `default` account is locked (`CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0` plus the mounted
  `users.d` config); the application connects as the dedicated `MILHOUSE_CLICKHOUSE_APP_USER`.
- Resource guidance: the `nofile` ulimit is raised for ClickHouse; set the `deploy.resources` memory
  limit to fit your host.

## Migrate the schema

Point your Milhouse config's `[storage.clickhouse]` at this server (the `*_env` references resolve to
`MILHOUSE_CLICKHOUSE_URL` / `USER` / `PASSWORD`), then:

```console
$ milhouse --config ./config.toml storage status    # read-only: applied vs pending
$ milhouse --config ./config.toml storage migrate    # apply the packaged migrations
```

## Back up and restore (native BACKUP/RESTORE)

This deployment provisions a ClickHouse `backups` disk in `config.d/backups.xml` (declared under
`storage_configuration` and allow-listed under `<backups>`), backed by the durable
`clickhouse-backups` named volume mounted at `/var/lib/clickhouse/backups`. It is kept **separate
from the data volume**, so `docker compose down -v` (which resets `clickhouse-data`) does not delete
your backups. Without this disk, `storage backup` / `storage restore` fail with `Disk backups does
not exist`.

```console
$ milhouse --config ./config.toml storage backup nightly_2026_08_10     # native BACKUP DATABASE
$ milhouse --config ./config.toml storage restore nightly_2026_08_10     # RESTORE into an EMPTY db
```

- **Restore targets an empty database.** A native `RESTORE DATABASE` rejects a non-empty target, so
  `storage restore` refuses (issuing no drop and no restore) if the analytical database already holds
  a schema. Restore into a clean/fresh state root, or after intentionally dropping the lost database.
  In-place **overwrite with rollback is deferred to W16** — this command never overwrites live data.
- **Retention and permissions.** The `backups` volume grows with each archive; rotate and remove old
  archives on your own schedule (there is no automatic pruning here). The directory is written by the
  ClickHouse server user inside the container and is loopback-only — never exposed off-host. Treat
  the backup volume with the same restrictive, owner-only permissions and off-device-encryption
  guidance as any state backup (plan section 10.3); it can contain analytical record metadata.
- The composite SQLite control-state + spool + manifest backup (and verified clean-host restore
  drill) is **W16**; this is only the ClickHouse-side native backup.

## Opt-in live smoke (G04a evidence)

The offline test suite runs in CI. The **live** G04a checks (anonymous access fails, authenticated
access succeeds, a fresh deployment migrates to the full schema) run against a real server and are
**out of CI**. To run them on this host:

```console
$ docker compose --env-file .env up -d
$ MILHOUSE_LIVE_CLICKHOUSE=1 \
  MILHOUSE_CLICKHOUSE_URL=http://127.0.0.1:8123 \
  MILHOUSE_CLICKHOUSE_USER="$MILHOUSE_CLICKHOUSE_APP_USER" \
  MILHOUSE_CLICKHOUSE_PASSWORD="$MILHOUSE_CLICKHOUSE_APP_PASSWORD" \
  ./scripts/run_make.py test  # or: uv run pytest tests/live/test_clickhouse_smoke.py -m live
```

To start clean (a true fresh-deployment migration), first `docker compose down -v` to drop the data
volume.
