# Changelog

## Unreleased

- Approve the authoritative Milhouse OSS 1.0 implementation plan and W00-W18 gate model.
- Establish the public/private source boundary, file-level donor provenance, and pre-alpha status.
- Ratify locked architecture and engineering-process decisions through ADRs 0001-0015.
- Establish five Milhouse-native engineering skills, Codex discovery aliases, report-only gate review,
  sanitized compound learning, and explicit no-vendoring, privacy, egress, and mutation boundaries.
- Add privacy, threat-model, governance, support, DCO, and implementation-status artifacts.
- Remove stale duplicate workflow/publication instructions and harden issue/review privacy guidance.
- Add an evidence-linked GitHub Discussions engineering journal, maintainer announcement form, and
  inaugural pre-alpha architecture post while keeping release claims separately authorized.
- Begin the W01 foundation with the `milhouse-observability` distribution, typed `milhouse` import
  package, modular pre-alpha Click entry point, and explicit package-resource manifest.
- Separate bounded runtime, optional receiver, and development dependencies; add the uv 0.11.29
  reproducible lock and contributor-only locked setup path.
- Add the planned test topology, tracked synthetic JSON/JSONL fixtures, coverage enforcement,
  package inventory and empty-environment smoke checks, repository validators, and fail-closed
  security tooling.
- Add least-privilege immutable-action CI with a fail-closed aggregate `required-ci` result.
- Require every configured Dependabot ecosystem to resolve to a canonical directory and a
  Milhouse-approved manifest; retain GitHub Actions updates while deferring Python updates until the
  hosted updater supports the required uv version and container updates until their owning package
  selects the matching `docker` or `docker-compose` ecosystem.
- Replace scaffold setup guidance with W01 contributor, development, dependency, package, and
  security workflow documentation while reserving product initialization for W06.
- Add strict configuration v1 models, validated public examples, deterministic JSON Schema export,
  and offline `config validate` and `config schema` commands.
- Add deterministic canonical bytes, record IDs and content hashes, immutable record envelopes, and
  append-only feedback transition validation.
- Add installation-keyed pseudonyms, URL/path sanitization, untrusted evidence rendering, layered
  credential/PII redaction, and exact nested field allowlists.
- Add canonical `STATE_ROOT` resolution with contained runtime children and symlink-escape refusal,
  plus bounded explicit env-file loading with process/CLI/configured precedence, no discovery or
  interpolation, safe source metadata, and non-enumerating secret storage.
- Add runtime-generation-bound pseudonym-key primitives with staged, fsynced, atomic no-overwrite
  publication; ACL-free private `0700` parent and `0600` key enforcement; owner/link/identity and
  published-byte validation; wrong-key detection; value-safe failures; and explicit recovery from
  uncertain publication commits.
- Add injectable UTC wall and process-local monotonic clocks plus a strict internal ASCII elapsed-
  duration parser whose lower and upper bounds are supplied by each owning caller.
- Add a shared stable-error foundation, code-only unknown-error normalization, and injected
  allowlist-only structured operational events with no arbitrary-text or exception-detail fields;
  harden config-model rendering and bound schema diagnostics without echoing unknown keys or values.
  Raw Pydantic models are now private implementation details; the pre-alpha
  `milhouse.config.MilhouseConfig` and `milhouse.config.models` construction paths are removed in
  favor of the safe loader and schema APIs, and invalid-config wording is intentionally normalized.
- Add a fail-closed common egress matrix that requires explicit external-surface enablement and
  classification allowlisting, permanently denies restricted data, hard-caps sensitive output,
  and returns the mandatory record, summary, or metadata disposition for every planned surface.
- Prevent malformed URL parser failures from retaining rejected port values in chained exception
  graphs or formatted tracebacks.
- Normalize every public identity and record-model validation failure to one fixed, value-free
  Pydantic error before it can retain rejected values, hostile exception text, or nested contexts;
  prevent caller overrides, foreign-model coercion, repeated initialization,
  declared/unknown/underscore mutation, pickle state APIs, and unchecked copy/construct APIs from
  weakening the strict contract; preserve strict JSON validation, public JSON schemas, exact nested
  domain-model composition, and deterministic record wires.
- Pseudonymize marked POSIX, network, tilde, relative, Windows, UNC, and `file:` paths in free text
  without a fixed mount-root allowlist, including repeated raw-space and shell-quoted continuations;
  ambiguous whitespace/path and nested delimiter boundaries fail with value-free diagnostics. Within
  HTTP URLs, classify one bounded decoded view and pseudonymize complete filesystem-root, PII, and
  double-encoding-ambiguous components while preserving `/api`, `/app`, and `/data` controls.
- Advance layered redaction to policy `r2`: compact collision-safe category markers, a final
  registered-secret invariant over generated pseudonyms and URLs, canonical-equivalent and nested
  percent/JSON/HTML/base64/hex decoding through two layers, base64 pad-bit/MIME aliases, standalone
  encoded local paths, unbracketed IPv6, and reviewed Linux/macOS filesystem-root segments at any
  URL path position. Malformed UTF-8 suffixes, non-UTF-8 neighboring bytes, odd/misaligned hex
  nibbles, and MIME whitespace after an outer codec cannot suppress a valid registered-secret span.
  Typed path allowlists now use the same collision-safe invariant.
- Detach accepted timestamps into exact built-in UTC datetimes and normalize secret-bearing
  `BaseException` failures from validation, clock, canonicalization, and content-hash boundaries to
  fixed value-free errors. Replace repeated outer-wrapper suffix scans with a bounded near-linear
  index for input-ceiling behavior.
- Validate enabled third-party plugin allowlist entries against a bounded, metadata-only view of
  installed path-backed distributions. Validation reads `METADATA`/`PKG-INFO` and
  `entry_points.txt` directly, applies respective 128 KiB and 64 KiB pre-parse byte caps, fails
  closed for unsupported metadata backends, and reuses one snapshot per configured distribution.
  Acceptance requires one exact raw distribution name, valid PEP 440 version (including epochs),
  entry-point group, and valid dotted `module:attribute` value; raw versions and entry-point values
  are then matched exactly. Validation never imports plugin code, never scans unlisted
  distributions, and returns fixed value-free configuration failures for missing, ambiguous,
  malformed, oversized, unsupported, or drifted metadata.
- Add immutable synthetic identity portability vectors and independent-process recomputation across
  mapping orders, hash seeds, timezones, and locales. Make the same contract aggregate-required on
  fixed macOS 14 with Python 3.11 and 3.14 while the existing Ubuntu matrix covers Python 3.11-3.14.
- Accept a raw JSON record draft that omits optional correlation data by strictly revalidating the
  exact model default instead of attempting to JSON-encode that already-constructed nested model.
