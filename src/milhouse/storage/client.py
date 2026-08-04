"""Typed, authenticated ClickHouse client seam (W04, plan section 4.5).

:class:`ClickHouseClient` is the minimal surface the migration runner and (later) the exporter and
query repository depend on. :class:`ConnectedClickHouseClient` is the real implementation over
``clickhouse-connect``; it is constructed from :class:`StorageClickHouseConfig` with the URL, user,
and password resolved through the existing secret pipeline. Construction opens **no** socket — the
driver is created lazily on first use — so the runner's logic is fully unit-testable against a fake
client, and no credential is ever read until a command actually runs.

Per-record egress enforcement (privacy class against ``EgressSurface.LOCAL_CLICKHOUSE``) lives on
the exporter write path added in the next W04 increment, not on this connection primitive; the DDL
this seam carries for migrations contains no record payload.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlparse

from milhouse.config import SecretEnvironment
from milhouse.config._models import StorageClickHouseConfig
from milhouse.storage.errors import StorageError


@runtime_checkable
class ClickHouseClient(Protocol):
    """The command/query surface the storage runner depends on."""

    def command(self, statement: str) -> None:
        """Execute one DDL/DML statement, discarding any result."""

    def query(self, statement: str) -> Sequence[Sequence[Any]]:
        """Execute one SELECT and return its result rows as a sequence of row sequences."""


@dataclass(frozen=True, slots=True, repr=False)
class _Endpoint:
    # repr suppressed: this holds the plaintext password for the client's lifetime; never let a
    # debug log or crash reporter serialize it (mirrors CliState/SecretEnvironment).
    host: str
    port: int
    secure: bool
    username: str
    password: str
    connect_timeout: int

    def __repr__(self) -> str:
        return f"_Endpoint(secure={self.secure}, resolved=True)"

    __str__ = __repr__


def _endpoint(config: StorageClickHouseConfig, secrets: SecretEnvironment) -> _Endpoint:
    if type(config) is not StorageClickHouseConfig:
        raise StorageError("MH_STORAGE_CONFIG", "a ClickHouse storage config is required")
    try:
        url = secrets.require(config.url_env)
        username = secrets.require(config.username_env)
        password = secrets.require(config.password_env)
    except Exception as error:  # secret pipeline raises a value error on a missing reference
        raise StorageError(
            "MH_STORAGE_CONFIG", "ClickHouse url/username/password references must resolve"
        ) from error
    try:
        parsed = urlparse(url)
        port = parsed.port  # raises ValueError on an out-of-range or non-numeric port
    except ValueError as error:
        raise StorageError(
            "MH_STORAGE_CONFIG", "the ClickHouse url must have a valid port"
        ) from error
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise StorageError("MH_STORAGE_CONFIG", "the ClickHouse url must be an http(s) endpoint")
    secure = parsed.scheme == "https"
    return _Endpoint(
        host=parsed.hostname,
        port=port if port is not None else (8443 if secure else 8123),
        secure=secure,
        username=username,
        password=password,
        connect_timeout=config.connect_timeout_seconds,
    )


class ConnectedClickHouseClient:
    """A ``clickhouse-connect`` client that opens its socket lazily on first command/query."""

    __slots__ = ("_driver", "_endpoint")

    def __init__(self, endpoint: _Endpoint) -> None:
        self._endpoint = endpoint
        self._driver: Any = None

    def _connected(self) -> Any:
        if self._driver is None:
            import clickhouse_connect  # type: ignore[import-untyped]  # no upstream stubs

            # Connect database-agnostic (the built-in ``default``). The runner and every storage
            # statement fully-qualify the target database (``<database>.table``), so the client can
            # create the target database on a fresh deployment where it does not exist yet.
            self._driver = clickhouse_connect.get_client(
                host=self._endpoint.host,
                port=self._endpoint.port,
                secure=self._endpoint.secure,
                username=self._endpoint.username,
                password=self._endpoint.password,
                database="default",
                connect_timeout=self._endpoint.connect_timeout,
            )
        return self._driver

    def command(self, statement: str) -> None:
        try:
            self._connected().command(statement)
        except Exception as error:
            raise StorageError("MH_STORAGE_CLIENT", "a ClickHouse command failed") from error

    def query(self, statement: str) -> Sequence[Sequence[Any]]:
        try:
            return list(self._connected().query(statement).result_rows)
        except Exception as error:
            raise StorageError("MH_STORAGE_CLIENT", "a ClickHouse query failed") from error

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:  # pragma: no cover - defensive: close of our own driver
                pass
            self._driver = None


def build_client(
    config: StorageClickHouseConfig, secrets: SecretEnvironment
) -> ConnectedClickHouseClient:
    """Construct a ClickHouse client from config + resolved secrets. Opens no socket here."""

    return ConnectedClickHouseClient(_endpoint(config, secrets))
