# Setup

Run:

```bash
./setup.sh
```

The setup script:

- creates `.venv`
- installs the local package in editable mode
- copies `.env.example` to `.env` if missing
- copies `config/example.toml` to `config/milhouse.toml` if missing
- creates ignored local state directories

The setup script must not:

- overwrite `.env`
- overwrite `config/milhouse.toml`
- install launchd or systemd services by default
- call live provider APIs
- require production credentials
- write to application repos

## ClickHouse

Local ClickHouse is the default store.

```bash
docker compose -f ops/clickhouse/docker-compose.yml up -d
```

The schema will be added under `schema/clickhouse/` as reusable source is migrated.
