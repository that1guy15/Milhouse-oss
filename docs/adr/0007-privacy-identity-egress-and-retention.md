# ADR 0007: Privacy, identity, egress, and retention

- Status: Accepted (ratification)
- Date: 2026-07-18
- Amended by: ADR 0016 (adds the `local_log` egress surface and the persisted structured-log contract, 2026-07-22); Addendum A07 (installation-key provenance and reserved compaction-namespace upgrade, 2026-08-01)

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

Owner-approved 2026-08-01 to resolve two P1s an independent review found in the W03 compaction/audit
remediation. It scopes the boundary between W03 and `init` (W06) and preserves every privacy invariant
above; it changes no wire byte, retention rule, product scope, or release authority.

- **Installation pseudonym-key provenance.** A persisted keyed derivative is trustworthy only if it is
  produced by the installation's own key, not merely by an object of the right class (`Pseudonymizer`
  is constructible from any 32 caller-supplied bytes). `init` (W06) owns creating the installation
  pseudonym-key file at the config/paths-bound location. **W03 compaction establishes provenance by
  LOADING** the key inside the validated config/runtime-path boundary
  (`load_pseudonym_key(config, paths)`, which enforces the bound path plus owner/mode/`nlink`/ACL
  checks) — it does not accept a caller-supplied key — and **fails closed before any file, ledger,
  cursor, or audit mutation** when the key is absent (unprovisioned installation), unloadable, or
  invalid. The lower audit constructor is non-optional on the compaction path. Consequently compaction
  cannot run on an un-`init`'d installation; that is a fail-closed contract, recorded honestly, not a
  passing path. Retention/purge keyed derivatives follow the same provenance rule where they key an id.

- **Reserved compaction-successor namespace and upgrade.** The `c[0-9a-f]{64}` successor namespace is
  reserved from the schema that introduces it (schema 10); no producer may commit into it. Those ids
  were producer-writable before the reservation, so on acquisition/upgrade a restartable
  exclusive-barrier check inventories any pre-existing committed segment in the reserved namespace and
  **fails closed with an operator-remediation code** rather than silently stranding a mixed segment.
  Because the upgrade guarantees the reserved namespace then contains only compaction successors, the
  single deterministic-slot successor allocation remains collision-safe. In pre-alpha (no released
  installs) this state is empty and the check is a deterministic, crash-safe no-op.

## Plan references

- [Section 4.7: trust, privacy, identity, egress, retention, and purge](../implementation-plan.md#47-trust-privacy-and-prompt-injection-boundary)
- [Section 4.15: structured log persistence (added by ADR 0016)](../implementation-plan.md#415-structured-log-persistence)
- [Section 10.1: threat-model boundaries](../implementation-plan.md#101-threat-model-assets-and-boundaries)
- [W02 and W03: privacy and retention implementation](../implementation-plan.md#w02--domain-configuration-identity-trust-and-privacy)
