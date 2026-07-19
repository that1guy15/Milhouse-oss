# ADR 0009: Scheduler, process, and service model

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Milhouse needs reliable local periodic work and optional inbound ingestion without adding a broker or silently installing background services.

## Decision

The scheduler is implemented with Python `asyncio`; Milhouse adds neither APScheduler nor a separate broker. `milhouse run` is the foreground scheduler, and `milhouse run --once` executes each due job once. Manual collector execution remains available through `milhouse collect run ID`.

Strict versioned `[[jobs]]` entries are the sole schedule/enablement authority. Jobs use interval, daily, or weekly schedules; interval timing is monotonic, calendar schedules resolve the configured IANA timezone to UTC including DST, and persisted times remain UTC. Each job has a SQLite lease, deterministic next run, bounded jitter, timeout, missed-run policy, backoff, independent failure domain, heartbeat, and non-overlap guarantee.

Cancellation is shielded during durable segment commit so shutdown completes durability or leaves a mandatory reconcilable artifact. Built-in jobs cover replay, curation/verification, notification retry, retention, daily/weekly reports, backup verification, and collectors/providers as their owning work packages become available.

The optional HTTP receiver is a separate foreground process launched by `milhouse receiver serve`; `milhouse run` never listens on a network socket. Scheduler and receiver have separate service templates and leases while sharing SQLite and spool through the multi-process commit protocol.

Setup and `init` install or start no service. launchd/systemd templates contain absolute installed executable/config paths and are rendered, installed, or removed only by explicit `milhouse service` commands.

## Consequences

Service tests cover dual schedulers, restart/cursor recovery, graceful interruption, stale jobs, provider isolation, DST, and clean-host templates. OS service management remains optional and visible.

## Plan references

- [Section 3.3: scheduler dependency policy](../implementation-plan.md#33-technology-and-dependency-policy)
- [Section 4.13: scheduler and process contract](../implementation-plan.md#413-scheduler-and-process-contract)
- [W15: scheduler and service gate](../implementation-plan.md#w15--long-running-scheduler-and-os-services)
