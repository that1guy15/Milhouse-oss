# Milhouse privacy model

Milhouse is local-first and observes potentially sensitive operational systems. Privacy is part of the data model and runtime ordering, not an optional output filter.

> **Pre-alpha:** this document is the binding 1.0 design contract. A control is not claimed operational until its owning work-package gate passes.

## Collection principles

- Collect only configured sources and allowlisted fields.
- Bound every request, file, record, page, query, and retained text value.
- Classify trust and privacy, then redact, before any persistence or egress.
- Treat provider, webhook, repository, issue, agent, and operator text as untrusted data.
- Never execute commands, SQL, code, URLs, or tool requests found in telemetry.
- Require explicit opt-in for agent summaries, structured traces, hosted storage, notifications, external issues, receiver remote bind, and MCP writes.

## Data classes

- **Public:** safe for configured public output.
- **Internal:** local operational metadata; external summary requires explicit policy.
- **Sensitive:** retained only in redacted local storage and policy-filtered local views; prohibited from repo briefs, Telegram, and GitHub Issues.
- **Restricted:** fail-closed input ceiling. The value is discarded and never becomes a canonical record. Only separately normalized safe reason metadata, counts, and a keyed fingerprint may survive.

## Agent data

Milhouse 1.0 never persists raw prompts, responses, transcripts, or tool output. Agent collection is disabled by default and may retain only versioned structured summaries and allowlisted trace categories/counts. Trace excerpts are invalid in config v1.

## Redaction and pseudonyms

Source allowlists are the primary control; layered secret/PII/path/URL redaction is defense in depth. Sensitive correlation uses an installation-local keyed HMAC, never a public unsalted hash. The key is created beneath `STATE_ROOT` with restrictive permissions, excluded from ordinary diagnostics/backups, and exportable only inside an explicitly encrypted recovery-secret envelope.

Redaction cannot make arbitrary free text risk-free. Milhouse bounds and labels retained text, blocks classified fields, and defaults external surfaces to summaries rather than evidence bodies.

## Retention

Defaults are:

| Class | Retention |
|---|---:|
| General events and agent summaries | 30 days |
| Metrics | 90 days |
| Runs | 180 days |
| Alerts, incidents, and feedback | 365 days |
| Structured trace events and logs | 14 days |
| Reports | 90 days |
| Backups | Explicit operator policy |

Every record receives an immutable expiry on first commit. Delivered redacted spool records remain recoverable until class expiry. Pending records retry only until successful delivery or that privacy deadline. Retention and target purge are previewable, explicitly confirmed, resumable, and audited. Milhouse unlinks expired files but cannot promise forensic erasure on SSD, copy-on-write, snapshot, or journaled media; use encrypted volumes and platform/media sanitization where required.

## Egress

The public `milhouse.privacy.require_egress` primitive enforces the classification ceiling before a
surface may persist or render data. It returns the maximum permitted content disposition rather
than a Boolean: a caller authorized only for a policy-filtered summary or metadata must not treat
that result as permission to emit a complete redacted record. External surfaces are denied unless
both independently enabled and classification-allowlisted, and caller policy can only narrow the
fixed matrix below.

- Local spool/SQLite/ClickHouse: redacted public, internal, and sensitive data; never restricted.
- CLI/local stdio MCP: bounded public/internal results and policy-filtered sensitive summaries.
- Repository briefs: public/internal only.
- Telegram/GitHub Issues: public or explicitly enabled internal summaries only.
- Hosted ClickHouse: separate opt-in with a classification allowlist.
- Diagnostics: local preview, metadata/redacted content only, never automatic upload.

This primitive is implemented in the current candidate and exhaustively matrix-tested. Operational
acceptance remains gated on G02 and on each later storage, CLI, report, MCP, diagnostics, and
notification work package invoking it and producing only the returned content shape; their sinks
are not yet implemented.

Milhouse has no call-home telemetry, crash upload, usage analytics, or update beacon.

## Operator responsibilities

Operators control source credentials, file permissions, host/disk encryption, backup encryption/location, retention choices, provider permissions, external destinations, plugin installation, repository access, and legal/compliance requirements. Third-party plugins run as trusted local code with the Milhouse user's authority and are not sandboxed.

See [the threat model](docs/threat-model.md), [Security](SECURITY.md), and plan section 4.7 for the exact egress/identity/purge contracts.
