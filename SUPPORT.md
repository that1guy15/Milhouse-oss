# Milhouse support policy

## Current status

Milhouse is pre-alpha. There is no supported production release and no guaranteed response time. Development questions and synthetic bug reports may use GitHub Issues or Discussions; security/privacy reports must follow [SECURITY.md](SECURITY.md).

Do not attach credentials, real telemetry, private paths, raw agent content, local state, database/spool files, generated reports, or user/customer data to a support request.

## Planned 1.x compatibility

The 1.0 target supports:

- Python 3.11-3.14;
- macOS 14 or newer, tested on the minimum and latest generally available release at RC;
- Ubuntu 22.04 and 24.04 LTS;
- the ClickHouse 26.3 LTS reference line and 25.8 compatibility line only while receiving security updates;
- local stdio MCP;
- Docker Engine/Compose for the reference ClickHouse deployment.

WSL2, Podman-compatible Compose, and externally managed/hosted ClickHouse are documented but not release-blocking. Native Windows services, multi-tenant hosting, a bundled web dashboard, remote MCP, raw agent-content storage, and automatic application mutation are outside 1.0.

After `1.0.0`, the project supports the current minor line and keeps at least the previous minor schema readable during 1.x. Readers accept explicitly supported predecessors; writers emit the current schema. Deprecations remain documented for at least one minor release unless security/data integrity requires faster removal. PyPI artifacts are never overwritten; a defective release is yanked and replaced by a patch.

## Useful reports

Include Milhouse/package version, OS/Python, redacted config schema version, exact command, synthetic reproduction, expected/actual behavior, and safe validation output. Use `diagnostics preview` before a diagnostics bundle once that command passes G06; diagnostics remain local and are never automatically uploaded.

Provider adapters without owner-authorized current sandbox evidence are labelled experimental rather than supported.
