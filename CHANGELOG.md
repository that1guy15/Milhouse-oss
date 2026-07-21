# Changelog

## Unreleased

- Approve the authoritative Milhouse OSS 1.0 implementation plan and W00-W18 gate model.
- Establish the public/private source boundary, file-level donor provenance, and pre-alpha status.
- Ratify locked architecture and engineering-process decisions through ADRs 0001-0015.
- Establish five Milhouse-native engineering skills, Codex discovery aliases, report-only gate review,
  sanitized compound learning, and explicit no-vendoring, privacy, egress, and mutation boundaries.
- Add privacy, threat-model, governance, support, DCO, and implementation-status artifacts.
- Remove stale duplicate workflow/publication instructions and harden issue/review privacy guidance.
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
