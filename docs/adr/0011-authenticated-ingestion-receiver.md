# ADR 0011: Authenticated ingestion receiver

- Status: Accepted (ratification)
- Date: 2026-07-18

## Context

Backend-relayed errors and webhooks need optional local ingestion, but browser credentials, unauthenticated remote binding, ambiguous canonicalization, and replay are unacceptable.

## Decision

The receiver is an optional Starlette/Uvicorn extra, disabled and bound to `127.0.0.1` by default. Remote binding requires `allow_remote = true`, an explicit CLI acknowledgement, and documented TLS termination. It runs only as the separate `milhouse receiver serve` foreground process.

Receiver endpoints and strict `[[receiver.sources]]` source/target/path mappings are exactly those in plan section 4.12. Query strings and noncanonical paths are rejected. Default bounds are 256 KiB/request, 100 records, 60 requests/minute/source, five-minute clock skew, and ten-minute nonce retention.

HMAC-v1 signs this exact byte sequence:

```text
v1\n<timestamp>\n<nonce>\n<UPPERCASE_METHOD>\n<canonical_path>\n<SHA256_HEX(raw_body)>
```

The request supplies `X-Milhouse-Signature: v1=<lowercase-hex-HMAC-SHA256>`, compared in constant time. Timestamp syntax is canonical Unix seconds; nonces are bounded printable ASCII and rejected transactionally on replay. Previous-secret rotation requires both a previous-secret environment reference and a future UTC expiry, and its use is audited.

GitHub webhooks instead use the exact raw body, `X-Hub-Signature-256`, configured repository/target mapping, configured secret, and durable delivery-ID idempotency. Browser events are relayed by an application backend; Milhouse publishes no browser-held secret pattern. Authentication does not elevate payload trust above `remote_untrusted`.

## Consequences

The receiver uses the same validation/redaction/spool pipeline as collectors. Tests cover signatures, canonicalization, nonce races, duplicate delivery, secret rotation, proxies, restart, multi-process rate limits, malformed/oversized bodies, remote binding, and absence of raw rejected data.

## Plan references

- [Section 4.12: ingestion receiver contract](../implementation-plan.md#412-ingestion-receiver-contract)
- [Section 4.1: receiver-source configuration](../implementation-plan.md#41-configuration-v1)
- [W07: authenticated ingestion gate](../implementation-plan.md#w07--generic-file-and-authenticated-ingestion)
