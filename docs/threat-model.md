# Milhouse threat model and data inventory

> Pre-alpha design model for plan version 1.0. Controls become operational only after their owning gate and tests pass.

## Security objectives

1. No classified raw value reaches persistence or egress.
2. No acknowledged unexpired record is lost in tested crash/outage scenarios.
3. Untrusted telemetry cannot become code, SQL, a command, URL fetch, filesystem target, or agent instruction.
4. Milhouse cannot write outside approved state roots or configured `.milhouse/` directories.
5. External listeners, storage, notifications, issues, services, plugins, and MCP writes require explicit enablement.
6. Private donor material and supply-chain compromise cannot enter release artifacts unnoticed.

## Data inventory

| Asset | Owner | Classification | Location/egress | Default retention |
|---|---|---|---|---:|
| Config structure and secret references | Operator | Internal | Config file; redacted CLI/diagnostics | Until replaced/deleted |
| Credential values | Operator/provider | Restricted | Process environment or explicit env file; never canonical persistence/egress | Process/config-file lifetime controlled by operator |
| Pseudonym key | Installation operator | Sensitive secret | `STATE_ROOT/control`; encrypted recovery envelope only | Until explicit rotation/purge |
| Redacted events | Target operator | Public/internal/sensitive | Spool and optional local ClickHouse; bounded CLI/MCP | 30 days |
| Redacted metrics | Target operator | Public/internal/sensitive | Spool/local ClickHouse | 90 days |
| Run outcomes | Target operator | Internal/sensitive | Spool/local ClickHouse | 180 days |
| Alerts/incidents/feedback | Project operator | Internal/sensitive | Spool, SQLite projection, ClickHouse; summaries by policy | 365 days |
| Structured agent summaries | Repository/operator | Internal/sensitive | Opt-in spool/ClickHouse | 30 days |
| Structured trace categories/counts | Repository/operator | Internal/sensitive | Opt-in spool/ClickHouse | 14 days |
| Raw prompts/responses/transcripts/tool output | Source user/provider | Restricted | Transient parser input only; never persisted or egressed | None |
| SQLite control/index metadata | Installation operator | Internal/sensitive | Local state and encrypted backup policy | Bounded by referenced record/control lifecycle |
| Reports and repo briefs | Target/repository owner | Public/internal | Local reports or configured `.milhouse/` | 90 days for reports; briefs atomically replaced |
| Operational logs | Installation operator | Internal | Local rotated structured-log JSONL via the `local_log` egress surface (plan section 4.15) | 14 days |
| Diagnostics | Installation operator | Internal/redacted metadata | Local previewed bundle only | Explicit operator deletion/policy |
| Backups | Installation operator | Same as included telemetry | Restricted local/off-device storage; encryption required off device | Explicit manual policy disclosed in manifest |
| Receiver nonces/idempotency | Installation operator | Internal metadata | SQLite | 10 minutes for nonces; operation policy for idempotency |
| Notification/issue delivery metadata | Installation/operator | Internal | SQLite; redacted destination metadata only | Item/control lifecycle |

Every asset has an accountable owner, classification, location/egress rule, and retention policy. Target purge lists immutable backups separately because it cannot rewrite undisclosed/offline copies.

## Trust boundaries and controls

| Boundary/threat | Prevention | Detection | Recovery/response | Required tests |
|---|---|---|---|---|
| Provider/file/webhook content contains secrets, PII, prompt injection, local/file-URI paths, or oversized input | Strict source models, allowlists, byte/page/record bounds, trust/privacy class, value-free domain failures, redaction before persistence | Safe reason codes, redaction counts, schema-drift/health events | Drop restricted value; quarantine only already-redacted conflict metadata | Adversarial nested/encoded/Unicode/markup/injection/path/size corpus across exception, record, and rendered surfaces |
| Filesystem traversal, symlink escape, unsafe repository writes | Canonical approved roots, no CWD lookup, `open`/replace policy, exact `.milhouse/` ownership | Audit failure and unhealthy status | Refuse write; preserve prior file | Traversal, symlink race, absolute/relative escape, permission tests |
| Crash between file and SQLite commit | Self-describing fsynced segment, rename+directory fsync, ledger commit before acknowledgement | Startup/writer reconciliation, digest/ledger verification | Register valid orphan; report missing ledger file unhealthy; replay idempotently | Kill injection at every commit/cursor/derivation/export/checkpoint boundary |
| ClickHouse outage/corruption/exposure | Loopback bind, non-empty least-privilege credentials, digest pin, spool authority | Health/checkpoint lag, migration checksums, data-count parity | Rebuild/replay from retained spool and verified backup | Auth failure, 24-hour outage drain, native restore, duplicate replay |
| Receiver spoof/replay/DoS | Loopback default, exact HMAC wire format, nonce transaction, clock/body/rate bounds, explicit remote acknowledgement | Auth/replay/rate audit metadata | Reject without raw persistence; rotate source secret | Signature vectors, replay/restart, skew, proxy, duplicate delivery, rate tests |
| SSRF or malicious redirects | HTTPS/host allowlists, GET-only generic admin API, redirect off by default, block local metadata/private destinations unless explicitly local | Safe refusal/health event | Disable/degrade source without stopping others | Scheme, DNS/IP, redirect, metadata endpoint tests |
| MCP overreach or injection | Local stdio, typed filters, fixed limits, read-only default, dual write enablement, no SQL/path/URL/actor authority | Audit each write and bounded-result metadata | Disable writes/server; replay idempotency record | Official-client conformance, cancellation, limit, duplicate and prompt-injection tests |
| Malicious third-party plugin | No auto-install; configured path-backed metadata only; 128 KiB `METADATA`/`PKG-INFO` and 64 KiB `entry_points.txt` pre-parse caps; unsupported backends fail closed; exact raw name, PEP 440 version, group, and valid dotted `module:attribute`; no unlisted scan or validation-time import; W05 revalidates and binds the exact object immediately before load; honest trusted-code model | Load failure isolation and safe package metadata in health | Disable/remove plugin and rotate affected credentials; no sandbox claim | Disabled zero-discovery, oversized/unsupported metadata, PEP 440 epoch and exact-version drift, malformed dotted values, snapshot reuse, exact mismatch, duplicate, no-import, metadata-drift, failure-isolation, and provenance checks |
| Persistence/output classification laundering | Common fail-closed surface matrix returns a required record, summary, or metadata disposition; caller allowlists can only narrow it; restricted is always denied | Stable value-free refusal codes and downstream audit metadata | Refuse the boundary and keep the source value out of the sink | Exhaustive surface/class matrix, property tests, hostile-policy error-graph corpus |
| External notification/action leaks or duplicates | Disabled default, common egress matrix, classification allowlist, egress redaction, preview/confirm, least-privilege token, idempotent marker | Delivery/audit state without secret-bearing URL/body | Disable sink, rotate token, retry safely or hold | Markdown injection, redaction, retry/rate/duplicate tests |
| Backup/purge races or incomplete destruction | Global shared/exclusive commit barrier, snapshot-derived segment set, target maintenance fence, manifest digest | Verify watermarks/hashes; unhealthy partial operation | Resume/rollback to new root; tombstone and list immutable backups | Concurrent writer, crash backup/purge, clean-host restore tests |
| Dependency/workflow/artifact compromise | Locked dependencies, full-SHA Actions, read-only workflow permissions, scans, build once, SBOM/provenance | Dependabot, dependency review, CodeQL, gitleaks, artifact inventory | Hold/yank release, advisory, patch from reviewed source | Fork CI without credentials, generated canary detection, and separate provenance/SBOM verification |
| Private donor contamination | Read-only fixed baseline, file-level disposition, synthetic fixtures, no private history | Identifier/history/package scans and independent provenance review | Remove and independently rewrite; block affected gate/release | Full-tree/history scans and package inventory |

## Residual risks

- Installed plugins execute with the Milhouse user's authority.
- An exact metadata match is an authorization precondition, not a signature, provenance guarantee,
  sandbox, or safety verdict; operators remain responsible for what they install and allowlist.
- Local administrators and compromised user accounts can read local data/keys unless host controls prevent it.
- Pattern redaction cannot safely preserve arbitrary free text; allowlists and restricted fail-closed handling remain necessary.
- Filesystem unlink is not guaranteed forensic erasure on modern media.
- Hosted providers and notifications have their own retention/security behavior after explicitly allowed egress.
- A producer that destroys unacknowledged outbox bytes causes detectable P1 loss but Milhouse cannot reconstruct deleted data.

## Review cadence

Update this model with every new input, persistence layer, egress surface, plugin capability, migration, or release workflow. W17 requires independent review of this file, security-critical modules, workflows, provenance, and artifacts; G18 cannot pass with an unresolved P0/P1 finding.
