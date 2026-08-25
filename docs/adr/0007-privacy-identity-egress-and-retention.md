# ADR 0007: Privacy, identity, egress, and retention

- Status: Accepted (ratification)
- Date: 2026-07-18
- Amended by: ADR 0016 (adds the `local_log` egress surface and the persisted structured-log contract, 2026-07-22); Addendum A07 (installation-key provenance and reserved compaction-namespace upgrade, 2026-08-01); Addendum A08 (dependency-ready key lifecycle and complete successor-set recovery, 2026-08-02); Addendum A09 (defers the W03 audited mixed-expiry compaction rewrite and withdraws its reserved namespace and migrations 11–12, 2026-08-03)

## Context

Every telemetry and repository source can contain secrets, private content, malicious instructions, or identifiers. Privacy controls must precede all persistence and egress.

## Decision

Milhouse applies strict source models, allowlist normalization, trust/privacy classification, and layered redaction before spool, SQLite, ClickHouse, logs, terminal output, reports, diagnostics, notifications, or MCP. Validation/redaction failures persist only safe reason metadata and keyed fingerprints. `restricted` input is a fail-closed ceiling and never becomes a canonical persisted or egressed record.

All provider, repository, webhook, issue, agent, and operator text is untrusted data. Milhouse does not execute commands, SQL, URLs, code, or tool calls found in telemetry. Raw prompts, responses, transcripts, tool output, credentials, cookies, signed URLs, user content, and raw local paths are not stored. Agent summaries and structured trace categories are opt-in; trace excerpts are invalid in config v1.

`init` creates a 32-byte installation-local HMAC pseudonym key beneath `STATE_ROOT` with mode `0600` and records only its non-secret ID/version. Ordinary backups exclude it. It may enter a backup only through an encrypted recovery-secrets envelope with an explicit recipient. Restore, loss, wrong-key handling, new identity, bounded rotation overlap, and pseudonym epochs follow plan section 4.7.

The egress matrix in plan section 4.7 is binding. Telegram, GitHub Issues, and hosted ClickHouse are independent, explicit opt-ins; sensitive data is prohibited from Telegram/GitHub, and restricted data is prohibited everywhere. Diagnostics are local, previewable, redacted, and never auto-uploaded.

Default class retention is 30 days for events/agent summaries, 90 for metrics/reports, 180 for runs, 365 for alerts/incidents/feedback, 14 for structured traces/logs, and manual policy for backups. Spool and projections honor each record's immutable expiry. Pending records retry only until that privacy bound. Compaction and retention are previewable, restartable, audited, and explicitly confirmed.

Target purge requires an exact dry-run manifest/digest, explicit target confirmation, exclusive fences across every writer, verified spool/SQLite/ClickHouse/report removal, a metadata-only tombstone, and separate disclosure of immutable backups.

## Consequences

No sink may weaken classification or redaction. Privacy and security tests plant secrets, PII, encoded values, prompt injection, unsafe markup, paths, and symlinks across every surface. Encrypted volumes remain operator guidance because Milhouse cannot promise forensic erasure on all filesystems/media.

## Addendum A07 (2026-08-01) — installation-key provenance and reserved compaction-namespace upgrade

Owner-approved 2026-08-01 to resolve the deep P1s that independent reviews found in the W03
audited-compaction remediation (defects D07/D08). It scopes the boundary between W03 and `init` (W06)
and preserves every privacy invariant above; it changes no wire byte, retention rule, product scope, or
release authority. The formal change-control record (reason, alternatives, compatibility, migration,
security, and revised tests) is in [plan section 1](../implementation-plan.md#1-authority-and-change-control);
this addendum states the resulting contract.

- **Installation pseudonym-key provenance (bound to the control-plane installation identity).** A
  persisted keyed audit derivative is trustworthy only if it is produced by *the installation's own*
  key. Neither an exact-type gate nor merely loading a file at the config-bound path proves that:
  `Pseudonymizer` is constructible from any 32 caller-supplied bytes, and a different installation's
  (or a restored/rotated) valid key can sit at the bound path. W03 therefore records the installation's
  **non-secret pseudonym key ID and epoch in the SQLite control plane** (migration 11, the singleton
  `_installation_key` table). `init` (W06) writes that record when it creates the key file. Compaction
  (a) binds the config/runtime `state_root` to the control database's own state root, (b) reads the
  recorded key ID/epoch, and (c) loads the key with
  `load_pseudonym_key(config, paths, epoch=<recorded>, expected_key_id=<recorded>)`, and **fails closed
  before any file, ledger, cursor, or audit mutation** when the record is absent (unprovisioned), the
  key is missing/unloadable/malformed, or its derived ID/epoch does not match the record. Compaction
  accepts no caller-supplied key and its audit constructor is non-optional. Until `init` establishes the
  record, compaction fails closed and cannot run — a fail-closed contract recorded honestly, not a
  passing path. Retention/purge keyed derivatives follow the same provenance rule where they key an id.

- **Reserved compaction-successor namespace, unexported authority, and auto-converging upgrade.** The
  `c[0-9a-f]{64}` successor namespace is reserved from schema 10. The producer commit ingress rejects
  it, and every public/general publication surface (`publish_segment_bytes`, `write_spool_segment`)
  rejects a reserved name with **no caller-selectable bypass**; only compaction publishes into the
  namespace, through an **unexported, reserved-only publication authority** bound to the exact successor
  identity. Because `c`+64-hex is itself a legal producer batch id, a pre-reservation schema could hold
  a committed reserved-namespace segment. On acquisition a **restartable exclusive-barrier remediation
  auto-converges** such a legacy occupant by rewriting it to a fresh non-reserved id — preserving every
  record, re-pointing cursors, and retiring the old file under a durable tombstone — so a legal upgraded
  install is **never wedged** and no expired data is retained. Migration 12's authoritative intent
  table starts empty on upgrade, so the first exclusive pass reconstructs and verifies any genuine
  pre-intent old-source/successor crash pair and atomically finishes that swap before rehoming the
  remaining unproven reserved rows. Rehome allocations are durably bound collision-resistant 256-bit
  ordinary IDs; allocation retries finite producer occupation without a probe bound or SQLite sequence
  ceiling and replaces a recorded target only after it is verified foreign while the source remains
  authoritative. Because the upgrade guarantees the
  reserved namespace then contains only compaction successors, the single deterministic-slot successor
  allocation stays collision-safe. Compaction additionally records a **durable retirement tombstone for
  the superseded old segment in the same transaction as the ledger swap**; reconciliation completes that
  deletion only behind a positive day-directory durability fence and never re-adopts the retired bytes,
  so a commit-uncertain unlink cannot resurrect a privacy-expired segment. In pre-alpha (no released
  installs) the legacy-occupant state is empty and the remediation is a deterministic, crash-safe no-op.

## Addendum A08 (2026-08-02) — dependency-ready key lifecycle and complete successor-set recovery

Owner-approved 2026-08-02 to close the remaining P1s reproduced by the independent exact-head PR
#79 review. The formal reason, alternatives, compatibility/migration, security, and revised-test
record is in [plan section 1](../implementation-plan.md#1-authority-and-change-control). This
addendum narrowly supersedes A07 where A07 deferred key establishment to W06 and described recovery
as independent old-source/successor pairs.

- **W03 establishes its own installation-key prerequisite.** When migration 11 is applied but the
  `_installation_key` singleton is unset, the first confirmed compaction validates the canonical
  config/runtime/control-database state-root binding and takes the installation commit barrier. It
  securely loads a valid existing key at the bound owner-only path (including a file durably
  published before an interrupted row commit), or creates and durably publishes a new key. Only
  after a verified key exists does it transactionally record the non-secret ID and epoch. Retry
  adopts the exact unrecorded file; it never writes a row first or overwrites an existing key. Once
  recorded, the A07 expected-ID/epoch verification remains binding and wrong, missing, malformed,
  stale-epoch, or cross-installation key material fails before spool mutation. No caller-provided
  key object or arbitrary caller bytes are accepted.

- **Schema-11 recovery is set-based and atomic.** Under the exclusive barrier, recovery discovers
  and verifies the complete set of reserved successors uniquely derived from every still-present
  source before changing the ledger. This includes multiple successors published from that source
  at successive expiry boundaries. Recovery selects or publishes the deterministic successor for
  the frames live at recovery time, verifies it, and atomically re-points cursors, preserves any
  delivered exporter acknowledgement, removes the source and every redundant verified successor
  row, records each old-to-final audit lineage, and writes a digest-scoped retirement tombstone for
  every old file. Only after commit are the old files unlinked. Cross-source ambiguity or inability
  to prove the exact final target protects the complete affected set and fails closed without
  partial rehome/compaction. Repeated restart, reconciliation, and maintenance therefore converge
  to exactly one ledger/file copy of each live record.

## Addendum A09 (2026-08-03) — defer the W03 audited mixed-expiry compaction rewrite

Owner-approved amendment A09 defers the audited mixed-expiry compaction rewrite defined by this ADR
and the A07/A08 addenda out of package W03 and gate G03. Thirteen consecutive independent reviews
failed exclusively inside the compaction subsystem, which had no production caller and could not run
before W06 established its installation key; its content-derived successor id had spawned a reserved
namespace, legacy-occupant rehoming, durable intents, and crash-during-upgrade recovery for
scenarios impossible in a pre-alpha with no released install. The rewrite is a separately owned
obligation, reachable only once a runtime produces delivered mixed-expiry segments and W06 `init`
provisions the installation pseudonym key.

Contract after this addendum:

- W03 no longer implements or gates the mixed-expiry rewrite. The `_installation_key` (migration 11)
  and `_compaction_intents`/`_sequences` (migration 12) tables and the reserved `c[0-9a-f]{64}`
  successor namespace are withdrawn; the control schema returns to version 10. The retention
  retirement tombstone (migration 10) is retained. Because these migration numbers are withdrawn (not
  reserved) and control migrations are strictly contiguous, the next control migration to land takes
  slot 11: **W05 alerting claims migration 11 for the `_alert_rule_state` table** (schema 11). When
  the deferred installation-key and compaction tables are re-scoped in (W06/later) they take the next
  free contiguous migration numbers at that time — the "migration 11 = `_installation_key`" / "12"
  references elsewhere in this ADR and the plan describe the pre-A09 plan and are superseded here.
- Retention prunes only fully-expired segments, behind the durable retirement tombstone, and leaves
  a mixed-expiry segment classified and in place — never deleted, never egressed. Export withholds a
  mixed-expiry or fully-expired segment (fail-closed), so no expired record is ever forwarded and no
  privacy-expired record can outlive its deadline once the deferred rewrite lands.
- The keyed-pseudonym lineage requirement of this ADR is preserved and moves to the package that
  owns the installation-key lifecycle (W06 and the later compaction owner), rather than being
  established inside compaction. No wire byte, record envelope, privacy class, retention day, or
  egress rule changes. A future package reintroduces the rewrite behind its own accepted amendment
  and forward migration.

## Plan references

- [Section 4.7: trust, privacy, identity, egress, retention, and purge](../implementation-plan.md#47-trust-privacy-and-prompt-injection-boundary)
- [Section 4.15: structured log persistence (added by ADR 0016)](../implementation-plan.md#415-structured-log-persistence)
- [Section 10.1: threat-model boundaries](../implementation-plan.md#101-threat-model-assets-and-boundaries)
- [W02 and W03: privacy and retention implementation](../implementation-plan.md#w02--domain-configuration-identity-trust-and-privacy)
