# G03 supported-host physical-crash test procedure

Status: **procedure only — not yet executed.** This document specifies the manual, supported-host
physical-crash tests that remain pending for G03 acceptance (owner-provided evidence, E06). It is a
companion to [G03.md](G03.md); run it when a supported clean host is available (before G03 acceptance,
and again at the RC soak).

## Why this exists

The automated [crash/concurrency/failure-injection harness](../../tests/unit/_g03_harness.py) proves
every durable-write boundary **deterministically** by in-process fault injection and
restart-by-reconciliation: a fault is raised at a chosen syscall or SQLite statement, and a fresh
writer's mandatory reconciliation is treated as the "restart". That proves the *logic* is correct.

It does **not** prove behaviour under a **real** process death — a `SIGKILL` or a host power-loss
that stops the process at an arbitrary machine-code instruction, with in-flight page-cache and
filesystem-journal state that no in-process test can reproduce. G03 requires that "a kill before
rename exposes no partial batch" and "a kill after commit loses no acknowledged record" hold against
those real kills on each supported filesystem. This procedure produces that evidence.

The two are complementary: the harness is the fast, always-on regression; this procedure is the
periodic, host-specific acceptance evidence.

## Environment to record (per run)

Capture all of the following into the run's evidence file, because crash behaviour is
filesystem- and platform-specific:

- OS name + exact patch/build (e.g. `Ubuntu 24.04.1`, `macOS 14.6.1 (23G93)`), architecture.
- Filesystem and mount options of the directory holding `STATE_ROOT` (e.g. `ext4`, `apfs`,
  `data=ordered`, `barrier=1`). Power-loss results are only meaningful with write barriers enabled.
- Python version, and the exact repository commit under test (`git rev-parse HEAD`).
- For power-loss cases: the exact method used to cut power (hardware switch, hypervisor
  `stop`/`reset`, `echo b > /proc/sysrq-trigger`), since a clean hypervisor stop that flushes caches
  is a weaker test than a true power cut.

## Method

Each case uses three roles:

1. **Setup** — create a fresh `STATE_ROOT` (an initialized control database, `commit.lock`, and an
   empty `spool/` tree) and any preconditioning segments, using the W03 library API exactly as
   `tests/unit/_g03_harness.py::build_spool` and `commit_segment` do. Until the `milhouse` CLI exists
   (W06), the driver is a short Python script that imports `milhouse.spooling` / `milhouse.state`.
2. **Kill** — run a **driver subprocess** that performs one durable-write operation and, at the chosen
   boundary, either (a) is sent `SIGKILL` by a controller, or (b) is running when the host loses
   power. The boundary is reached by having the driver signal readiness (write a sentinel byte to a
   pipe / touch a file) immediately before the target syscall, then block; the controller kills it on
   the sentinel. This makes the kill point exact and repeatable without the driver ever completing the
   operation.
3. **Restart + verify** — from a new process, open the same `STATE_ROOT` (constructing a
   `DurableSpool` runs mandatory reconciliation — the real restart path) and assert the case's pass
   criteria against the ledger rows, the on-disk spool, and a `replay_segments` pass.

Record, for every case: the pre-kill state, the post-kill on-disk artifacts (before restart), the
post-restart state, and PASS/FAIL. Run each case **≥5 times** per filesystem; a single pass is not
sufficient because the kill can land in slightly different sub-states.

## Test cases

Each maps to a G03 assertion and to the deterministic harness test that already covers the logic.

### C1 — Kill before the atomic rename exposes no partial batch
- Harness analogue: `test_g03_failure_injection.py::test_a_kill_before_rename_exposes_no_partial_batch`.
- Setup: empty spool.
- Kill: driver stages+fsyncs the segment temporary, signals readiness, blocks *before* the atomic
  rename; controller `SIGKILL`s it (or power is cut here).
- Restart + verify: **no committed `pending/<day>/<batch>.jsonl` exists**, **no `_segments` row
  exists**, and the batch was never acknowledged (the driver never returned success). A staged
  temporary (`.milhouse-stage-*`) may remain; reconciliation must recover/quarantine it and it must
  never become a committed batch.

### C2 — Kill after commit loses no acknowledged record
- Harness analogue: `test_a_kill_after_commit_loses_no_acknowledged_record`.
- Setup: empty spool.
- Kill: driver commits the segment fully (the commit returns = acknowledged), records the acknowledged
  record ids to a durable side-file, signals readiness, then blocks; controller kills it.
- Restart + verify: the `_segments` row and durable file are intact, and `replay_segments` returns
  exactly the acknowledged record ids. **No acknowledged record is lost.**

### C3 — Kill during the ledger transaction (post-publish, pre/mid-commit)
- Harness analogue: `test_spool_commit.py` (ledger transaction failure) + `test_spool_reconcile.py`
  (orphan re-registration).
- Kill: driver publishes+fsyncs the file, then is killed during/just after the `BEGIN IMMEDIATE …
  INSERT` but before the transaction is durably committed.
- Restart + verify: either the row is present (commit was durable) **or** the file is a
  re-registrable orphan that reconciliation adopts into the ledger. **Never a `_segments` row without
  its file, and never a lost acknowledged record.**

### C4 — Kill during a source-cursor / derivation-checkpoint update
- Harness analogue: `test_a_cursor_update_fault_rolls_back_atomically`,
  `test_a_derivation_checkpoint_fault_rolls_back_atomically`.
- Setup: a committed segment and a cursor/checkpoint at revision N.
- Kill: driver advances the cursor/checkpoint to N+1 and is killed mid-transaction.
- Restart + verify: the stored revision is **exactly N or exactly N+1**, never a half-applied row,
  and its `(position, revision)` are internally consistent.

### C5 — Kill between destination confirmation and the exporter checkpoint
- Harness analogue: `test_an_exporter_checkpoint_fault_leaves_delivery_retryable`.
- Setup: a committed, undelivered segment with a fake exporter that confirms (returns) then writes a
  "confirmed" side-file.
- Kill: after the exporter confirms but before the delivery-status compare-and-set commits.
- Restart + verify: the exporter row is still `pending` (retryable). A re-delivery pass re-confirms
  and marks it `delivered` exactly once logically (**at-least-once physical, effectively-once
  logical** via the record ids). No duplicate logical record downstream.

### C6 — Concurrent writers under a kill produce valid non-interleaved segments
- Harness analogue: `test_g03_concurrent_writers.py`.
- Setup: empty spool.
- Kill: launch N independent writer subprocesses each committing M segments; `SIGKILL` a random
  subset mid-run (or cut power with all running).
- Restart + verify: after reconciliation, every segment that any writer *acknowledged* is present and
  valid; **no segment file is torn, interleaved with another's frames, or duplicated**; every present
  file's frames belong only to its own batch id. Unacknowledged in-flight commits leave at most a
  recoverable staged temporary.

### C7 — Kill during audited compaction
- Harness analogue: `test_spool_compaction.py` (interrupted-swap and interrupted-unlink convergence,
  and the foreign-id probe cases).
- Setup: a mixed-expiry segment (some records expired, some live), evaluated at a `now` past the
  expiry; optionally preoccupy the primary derived successor id with a foreign segment.
- Kill: at each of three sub-boundaries — (a) after the successor file is published, before the swap;
  (b) after the swap commits, before the old file is unlinked; (c) during the swap transaction.
- Restart + verify (run for each sub-boundary): **no unexpired record is ever lost**, the expired
  frames are removed by convergence (a later compaction pass finishes the retire), any foreign
  segment is untouched, and no live record is silently duplicated beyond a transient benign copy that
  a later pass resolves. Confirm the successor's `origin=reconciled` and reconstructed `committed_at`.

### C8 — Kill during a retention prune
- Harness analogue: `test_spool_retention_apply.py` (crash-during-prune convergence).
- Setup: a fully-expired committed segment (optionally cursor-referenced).
- Kill: after the row-first delete transaction commits, before the durable file is unlinked.
- Restart + verify: the ledger row is gone, the orphan file is re-registered by reconciliation, and a
  later retention pass re-prunes it to convergence. A referenced cursor is detached with its
  `(position, revision)` preserved. **A pending (undelivered) segment is never pruned before its
  record-class privacy expiry.**

### C9 — Torn tail from a power-loss mid-write
- Harness analogue: `test_spool_reader.py` / `test_spool_quarantine.py` (torn-tail rejection + valid
  frames preserved).
- Kill: cut power (or `SIGKILL`) while a segment file is being written, leaving a truncated tail.
- Restart + verify: the trusted reader rejects the torn file closed (`MH_SPOOL_TRUNCATED`);
  reconciliation quarantines it with a safe reason; any *previously committed* segments remain valid
  and replayable. Valid frames are never dropped because of a neighbouring torn file.

## Pass criteria (all cases)

- No acknowledged record is ever lost (the overriding W03 invariant).
- No `_segments` row exists without its durable file after reconciliation.
- No partial/interleaved/torn file is ever treated as a committed batch.
- Privacy-expired data is never retained past its hard deadline through any crash path, and expired
  data is never egressed mid-operation.
- Every convergence completes within a bounded number of restart+reconcile passes.

A run passes only when every case passes on every tested supported filesystem for the required
repetitions, with the environment recorded. File the completed run as dated evidence and link it from
[G03.md](G03.md).

## Open items / when to run

- Runnable **now** at the library level (C1–C9 via driver scripts + `SIGKILL`). True host power-loss
  (C9 and power variants of C1–C8) needs a supported clean host and, ideally, a hypervisor/hardware
  power control (E06).
- The driver becomes simpler once the `milhouse` CLI exists (W06); this procedure should be revisited
  then to drive the operations through the CLI as an operator would.
