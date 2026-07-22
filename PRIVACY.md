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

Marked local paths in retained free text are replaced as one keyed token. This includes POSIX
absolute/network paths, tilde and dot-relative paths, Windows drive/UNC paths, and complete `file:`
URIs, including their authority, query, and fragment. Separator-bearing continuations after raw
ASCII or Unicode spaces and shell-quoted components are consumed with the marked path. The raw
same-line scanner continues through repeated components until punctuation, markup, or a field label;
when the first separator appears only after multiple unseparated tokens, the path/prose boundary is
ambiguous and fails with a fixed value-free error. It also fails value-free rather than returning a
partial token when separator-free text remains after the last confirmed continuation separator.
Ambiguous cross-line input, unclosed delimiters, and nested backtick paths whose same-length run is
adjacent to another opening quote or markup tag follow the same rule. Valid outer quote and closing
HTML wrappers remain supported. Validated HTTP components are checked on one bounded decoded
comparison view before canonical re-encoding. Reviewed Linux and macOS filesystem-root segments,
including `/home`, `/Users`, `/var`, `/proc`, `/sys`, `/Library`, and `/Applications`, are detected
at any URL path position. Encoded or raw drive/UNC paths, labeled filesystem paths, components
containing email, phone, IPv4, bracketed or unbracketed IPv6, and double-encoded ambiguity are
pseudonymized as complete URL path components. Paths outside those signatures, including `/api`,
`/app`, and `/data`, are preserved. Standalone local/file-URI paths encoded through one or two
percent-decoding layers receive the same typed-path treatment. An unprefixed value such as
`dir/file` is ambiguous in prose and must enter through an explicitly typed path field to receive
path treatment.

Layered redaction policy `r2` removes registered values in literal, canonical-equivalent Unicode,
percent, JSON escape, HTML entity, base64/base64url (including valid pad-bit aliases and MIME
whitespace), and hexadecimal forms. Every ordered pair of those supported decoding families is
checked to a total depth of two under the input bound. MIME whitespace remains recognized after an
outer decode, and malformed UTF-8 bytes or odd/misaligned hex nibbles adjacent to a valid registered
span cannot suppress that span. Generated pseudonyms and category markers are
checked again after restoration so they cannot reintroduce a registered value; a colliding typed
path or URL is replaced by a compact whole-value marker. These compact markers are shorter than the
minimum registered-secret length and are idempotent. Changing these normalization semantics changes
the redaction policy revision independently from the pseudonym-key epoch.

Public identity and record models reduce failed validation to a fixed error type and message with
no rejected input, model-owned nested location, context, or hostile exception text. Strictness,
extra-field rejection, instance revalidation, frozen assignment/deletion (including unknown
underscore state), exact concrete nested-model typing (including subtype rejection), and validated construction/copy semantics cannot be
weakened through the supported concrete-model entry points. Repeated initialization and validation
into an initialized model are refused, and pickle state export/restoration is disabled. Raw JSON
must enter through a concrete model's JSON validator; caller-created composite adapters can fail in
their outer
parser before a model boundary and are not Milhouse ingestion entry points. A `RecordDraftV1` is an
already-redacted domain value: callers must apply source allowlisting and redaction before draft
construction. The owning W05 runtime pipeline must enforce that ordering before it may persist or
egress a finalized record.

Accepted domain timestamps are copied into exact built-in UTC `datetime` values rather than
retaining caller-owned datetime subclasses or mutable timezone objects. Callback failures,
including non-`Exception` `BaseException` subclasses, are reduced to fixed value-free errors at the
domain, clock, canonicalization, and content-hash boundaries.

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

Operators control source credentials, file permissions, host/disk encryption, backup encryption/location, retention choices, provider permissions, external destinations, plugin installation, repository access, and legal/compliance requirements. Third-party plugins run as trusted local code with the Milhouse user's authority and are not sandboxed. Milhouse validates only explicitly allowlisted, path-backed installed plugin metadata without importing code. It applies byte caps before parsing the fixed metadata files, fails closed for unsupported metadata backends, neither inventories unlisted plugin distributions nor treats a metadata match as a privacy or safety guarantee.

See [the threat model](docs/threat-model.md), [Security](SECURITY.md), and plan section 4.7 for the exact egress/identity/purge contracts.
