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

## One ClickHouse per installation (enforced)

Milhouse's single-writer correctness rests on a machine-local commit barrier that fences exactly one
installation's writers. That barrier cannot see a **second** installation — a different state root,
clone, or host — pointed at the **same** ClickHouse, so two installations sharing one destination
would silently comingle and corrupt each other's data. The supported model is therefore **one
ClickHouse per installation**, and it is **enforced fail-closed**:

- `storage migrate` **claims** the destination for the local installation (a single-owner
  `_installation` row). A first migrate stamps ownership; a re-run by the same installation verifies.
- `storage export`, `storage backup`, and `storage restore` **refuse to run** unless the destination
  is owned by the local installation. A second installation pointed at a claimed destination — or a
  restore of another installation's backup, whose restored owner row names that other installation —
  fails closed with `MH_STORAGE_OWNERSHIP` (exit 1) rather than writing or comingling data.
- An **unclaimed** destination (never migrated) likewise refuses export/backup: run `storage migrate`
  first.
- On **upgrade of a pre-existing destination** (one migrated before this guard existed, so it has no
  `_installation` row yet), the **first** installation to `storage migrate` claims it — ownership is
  attributed to whoever migrates first, not retroactively to the original writer. In the supported
  one-per-destination model that is the sole rightful install; a destination that was already
  (incorrectly) shared is taken back by the rightful owner with `--reclaim`.

To **deliberately re-point** an installation at a new ClickHouse host (or take over a destination that
was claimed by an installation you are decommissioning), migrate with `--reclaim`, which supersedes
the prior owner:

```console
$ milhouse --config ./config.toml storage migrate --reclaim    # take ownership of this destination
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
- **A foreign or failed restore leaves the destination populated.** If the restored backup was taken
  by a *different* installation (its `_installation` owner row names another install), `storage
  restore` fails closed (`MH_STORAGE_RESTORE`, exit 1) **after** the native `RESTORE` has already
  materialized that data into the (empty) target. Recovering the clean precondition is a **manual
  `DROP DATABASE`** — automatic rollback of a failed/foreign restore is deferred to W16. (Restoring
  your OWN backup verifies its owner row and proceeds.)
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
