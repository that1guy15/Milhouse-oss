# ADR 0016: Local structured-log persistence

- Status: Accepted (ratification)
- Date: 2026-07-22
- Authority: Owner-approved plan amendments A02 (2026-07-22) and A05 (2026-07-23) under plan section 1 change control
- Amends: ADR 0007 (adds the `local_log` egress surface and the persisted structured-log contract)
- Corrected: 2026-07-23 gate-scope alignment (defect D02, plan amendment A04), owner-approved under plan section 1 change control — the G02 revised-validation is re-scoped to W02-owned evidence, and the dependency-blocked structured-log file, CLI/stderr/diagnostics, generated-report, and backup/restore/purge evidence is mapped to G03, G06, G09, and G16 per section 4.15

## Context

Plan version 1.0 exposes `[paths].logs`, `[runtime].log_level`, and `[retention].logs_days`, and W02
delivers an in-memory, constructor-controlled `StructuredLogEventV1` with an injected sink, but it
never defines the persisted-log wire, filesystem namespace, durability, rotation, recovery,
concurrency, or lifecycle semantics. Plan section 8.0 returns the plan to Draft when implementation
discovers an unstated stored contract, so those bytes cannot be chosen inside the implementation
without a numbered amendment. The egress matrix in section 4.7 also has no log surface, even though
operational logs are already an inventoried Internal, 14-day asset and redaction already precedes
logs.

## Decision

Plan amendment A02 adds normative section 4.15 and one `local_log` row to the section 4.7 egress
matrix. In summary:

- Structured logs are installation-scoped local operational metadata and never a record, audit,
  replay, verification, acknowledgement, or feedback authority; logging can never control or roll
  back record acknowledgement.
- The `local_log` surface authorizes only `public → metadata` and `internal → redacted metadata`;
  `sensitive` and `restricted` are denied through the single fail-closed `require_egress` matrix. No
  target IDs, paths, URLs, credentials, payloads, exception text, arbitrary messages, prompts,
  transcripts, responses, tool output, or provider content may enter the stored wire, stderr, or any
  exception or traceback. Safe counts and keyed fingerprints derived from rejected data are
  reclassified as internal metadata before this boundary.
- The stored wire is bounded `CanonicalJSONV1` UTF-8 JSONL (`StructuredLogHeaderV1`,
  `StructuredLogEventLineV1`, `StructuredLogTrailerV1`) with a `content_sha256` over the exact header
  plus ordered event-line bytes including their LFs and excluding the trailer. The event line has no
  arbitrary-text or exception-detail field, and the in-memory `StructuredLogEventV1` stays
  constructor-controlled with the stored line as a separate exact projection.
- Files resolve under the secured `[paths].logs` directory (mode `0700`; files `0600`) with
  descriptor-relative, no-follow, close-on-exec access and owner/regular-file/single-hard-link/safe-
  ACL/no-symlink/no-directory-replacement checks, failing closed when a platform protection is
  unavailable. Twenty-digit rotation sequences never reuse until a confirmed full purge; overflow
  fails closed.
- A successful emit is one appended line, not crash durability; flush, clean shutdown, and rotation
  fsync the active descriptor. Rotation and recovery use a fixed ordering across every write, fsync,
  and rename boundary; a torn tail truncates to its last LF while any other malformed, conflicting,
  foreign, or ambiguous state fails closed; closed rotations are immutable.
- The lock order is global barrier lease → `structured-log.lock` → descriptors, passing existing
  barrier authority through, with exclusive maintenance authority for recovery, retention, restore,
  and full purge, and never acquiring the global barrier while holding the log lock.
- Bounds are 4,096 bytes per event line, 1,024 bytes per header or trailer, 8 MiB per segment, 10,000
  enumerated rotations, and a five-second lock wait on injected monotonic time, with no compression in
  v1.
- Default retention stays 14 days, captured per segment; tightening may shorten an unexpired deadline
  and relaxation never extends a captured one. Backups exclude logs, restore preserves destination-
  host logs, target purge leaves installation logs to ordinary expiry, and confirmed full purge
  removes them under exclusive maintenance authority. Ownership splits across W02 (wire, encoder,
  `local_log` authorization, golden vectors, sink interface), W03 (persistence, crash recovery,
  multiprocess and global-barrier integration, retention preview/apply), W06 (CLI and stderr
  binding), and W16 (backup, restore, full purge).

The exact field lists, bounds, formats, transform order, and namespace are in plan section 4.15 and
section 4.7 and are binding rather than duplicated here.

## Alternatives considered

- **Choose the wire inside the implementation:** rejected because section 8.0 forbids an unstated
  stored contract and later tests would ratify accidental bytes for durable, cross-platform G02
  evidence.
- **stderr-only, no persisted log:** rejected because operational recovery, rotation, and retention
  need a durable local artifact; stderr instead reuses the exact event-line bytes without a file
  header, trailer, or sequence.
- **Treat spool records as logs:** rejected because records are privacy-bounded canonical evidence
  with their own durability and delivery contract; conflating them would put record authority behind
  an operational sink.
- **Standard-library rotating handlers:** rejected because their formatting, locking, rotation, and
  crash behavior are platform- and configuration-dependent and would admit arbitrary-text and
  exception detail into the wire.

## Compatibility and migration

No public stored-log format has shipped, so A02 introduces the wire at v1 with no migration and does
not implicitly adopt preexisting matching files, which are rejected. A future wire, projection,
namespace, or retention change requires a new version and a compatibility plan under plan section 1.
A02 changes no product scope, supported platform, record type, egress destination, or release gate,
and expands no retention beyond the existing 14-day log class.

## Security and privacy impact

The amendment closes fail-open logging interpretations: the log surface is authorized only through the
single fail-closed `require_egress` matrix (`restricted` is always denied), stays downstream of
allowlist normalization and redaction, resolves only under the configured runtime home logs path, and
carries no arbitrary-text or exception-detail field, so secrets, PII, paths, prompts, transcripts, and
tool output cannot reach files, stderr, exceptions, or tracebacks. Log failures emit only fixed safe
`MH_LOG_*` metadata and cannot recurse. No external log egress or private-donor logging reuse is
authorized, and the stored-log wire is a clean-room rewrite from the public plan.

## Revised validation

Gate G02 requires only the W02-owned evidence for this contract: golden `local_log` wire bytes across
Python 3.11-3.14, hash seeds, locales, timezones, Ubuntu, and macOS; secret, PII, path, prompt,
transcript, and tool-output canary absence from the projected wire bytes, the stream-sink output,
exceptions, and tracebacks; the fail-closed `local_log` egress authorization; the constructor-controlled
event projection with no arbitrary-text or exception-detail field; stream-sink hostile-failure
normalization and complete-write enforcement; the contained child-process disclosure oracle; and at
least 95% branch coverage for the W02 security-critical modules, including `core/log_wire.py`.

The dependency-blocked downstream evidence is validated at its owning gate, consistent with the section
4.15 ownership split, and G02 neither requires nor certifies it: filesystem persistence and security
(owner, mode, ACL, symlink, hard-link, and directory-swap negatives), multiprocess and global-barrier
integration, size/day/policy rotation, every write/fsync/rename crash boundary, torn-tail recovery and
corruption refusal, disk-full/short-write/lock-timeout/capacity/sequence-overflow failures,
acknowledgement isolation, and retention behavior are owned by W03 and validated at G03; the real
CLI/stderr binding and diagnostics bundle are owned by W06 and validated at G06; the concrete
generated-report surface is owned by W09 and validated at G09; and backup exclusion, restore
preservation, target purge (which leaves installation-scoped logs to ordinary expiry), and full-purge
behavior are owned by W16 and validated at G16. Requiring that downstream evidence for G02 would be a
gate cycle, because W03 depends on G02.

## Amendment A05: exact v1 stored schema (2026-07-23)

Owner-approved plan amendment A05 (2026-07-23), under plan section 1 change control, promotes the
section 4.15 stored-log wire to an exact, machine-checked v1 schema without changing any
already-implemented byte. For every stored line it fixes the literal keys and canonical order, the
literal `line` and `schema` values, scalar types, the explicit-`null` optionality rule (optional
values are never omitted), the RFC3339 UTC millisecond timestamp and 64-character lowercase-hex digest
encodings, the 1,024-byte header/trailer and 4,096-byte event byte bounds, the empty-segment semantics
(`event_count` `0` with explicit-`null` `last_event_at`), and the digest coverage over the header plus
ordered event lines excluding the trailer. It fixes the segment deadline as `expires_at = opened_at +
retention_days` days, captured at close, tighten-only, with W02 encoding the field and W03 computing
it, and binds the header `retention_days` domain to the `[retention].logs_days` 1-to-3,650-day
ceiling. Every stored line remains self-describing so the mixed-line JSONL stream is parseable line by
line.

Alternatives, compatibility, and security are as in plan amendment A05: the schema was previously
implicit in code and tests (rejected under section 1); the per-line version and line-type envelope is
required for mixed-line JSONL (reverting it is rejected); no public format has shipped, so the schema
is v1 with no migration and no implicit adoption of preexisting files; and the exact schema keeps
arbitrary text, exception detail, secrets, and provider content out of every line, stderr, exception,
and traceback, unchanged from A02.

Gate G02 additionally requires a machine-checked schema lock: exact normative vectors for the minimal
and maximal header, event, non-empty trailer, and empty trailer; the digest-coverage and empty-segment
digest; the `expires_at = opened_at + retention_days` vector; and a test that fails if any declared
key, literal, scalar type, or optionality rule drifts.

## Plan references

- [Section 1: authority, change control, and amendment A02](../implementation-plan.md#1-authority-and-change-control)
- [Section 4.7: trust, privacy, egress, and the `local_log` surface](../implementation-plan.md#47-trust-privacy-and-prompt-injection-boundary)
- [Section 4.15: structured log persistence](../implementation-plan.md#415-structured-log-persistence)
- [W02 and G02](../implementation-plan.md#w02--domain-configuration-identity-trust-and-privacy)
