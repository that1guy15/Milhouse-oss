"""Offline tests for the ClickHouse client wrapper: no socket at construction, secret resolution."""

from __future__ import annotations

from typing import Any

import pytest

from milhouse.config._models import StorageClickHouseConfig
from milhouse.config.secrets import SecretEnvironment
from milhouse.storage import StorageError, build_client


def _config(url_env: str = "MH_CH_URL") -> StorageClickHouseConfig:
    return StorageClickHouseConfig(
        enabled=True,
        url_env=url_env,
        username_env="MH_CH_USER",
        password_env="MH_CH_PASS",
        database="milhouse",
        connect_timeout_seconds=5,
    )


def _secrets(url: str = "http://127.0.0.1:8123") -> SecretEnvironment:
    return SecretEnvironment({"MH_CH_URL": url, "MH_CH_USER": "app", "MH_CH_PASS": "secret"}, {})


class _FakeDriver:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def command(self, statement: str) -> None:
        self.commands.append(statement)

    def query(self, statement: str) -> Any:
        raise AssertionError("not used")

    def close(self) -> None:
        pass


def test_build_client_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    def _fake_get_client(**kwargs: Any) -> _FakeDriver:
        calls.append(kwargs)
        return _FakeDriver()

    monkeypatch.setattr("clickhouse_connect.get_client", _fake_get_client)

    client = build_client(_config(), _secrets())
    assert calls == []  # construction resolved secrets but opened no connection

    client.command("SELECT 1")
    assert len(calls) == 1  # the socket opens lazily on first use
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8123
    assert calls[0]["secure"] is False
    assert calls[0]["username"] == "app"


def test_https_url_selects_secure_and_default_port(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "clickhouse_connect.get_client", lambda **kw: calls.append(kw) or _FakeDriver()
    )
    client = build_client(_config(), _secrets(url="https://clickhouse.internal"))
    client.command("SELECT 1")
    assert calls[0]["secure"] is True
    assert calls[0]["port"] == 8443


def test_missing_credential_reference_fails_closed() -> None:
    secrets = SecretEnvironment({"MH_CH_URL": "http://127.0.0.1:8123"}, {})  # user/pass absent
    with pytest.raises(StorageError) as captured:
        build_client(_config(), secrets)
    assert captured.value.code == "MH_STORAGE_CONFIG"


def test_non_http_url_is_rejected() -> None:
    with pytest.raises(StorageError) as captured:
        build_client(_config(), _secrets(url="tcp://127.0.0.1:9000"))
    assert captured.value.code == "MH_STORAGE_CONFIG"


def test_out_of_range_port_fails_closed_not_traceback() -> None:
    # urllib raises ValueError on an out-of-range port; it must become a fail-closed StorageError,
    # never an uncaught traceback out of the CLI.
    with pytest.raises(StorageError) as captured:
        build_client(_config(), _secrets(url="http://127.0.0.1:70000"))
    assert captured.value.code == "MH_STORAGE_CONFIG"


def test_endpoint_repr_never_reveals_the_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _FakeDriver())
    client = build_client(_config(), _secrets())
    rendered = repr(client._endpoint)  # asserting the resolved credential never renders
    assert "secret" not in rendered
    assert "resolved=True" in rendered


def test_build_client_rejects_a_non_config() -> None:
    with pytest.raises(StorageError) as captured:
        build_client(object(), _secrets())  # type: ignore[arg-type]
    assert captured.value.code == "MH_STORAGE_CONFIG"


def test_command_wraps_a_driver_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeDriver):
        def command(self, statement: str) -> None:
            raise RuntimeError("driver failure")

    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _Boom())
    client = build_client(_config(), _secrets())
    with pytest.raises(StorageError) as captured:
        client.command("SELECT 1")
    assert captured.value.code == "MH_STORAGE_CLIENT"


def test_query_returns_rows_reuses_driver_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Result:
        def __init__(self) -> None:
            self.result_rows = [[1], [2]]

    class _Driver(_FakeDriver):
        def query(self, statement: str) -> Any:
            return _Result()

    driver = _Driver()
    calls: list[int] = []

    def _get(**kw: Any) -> _Driver:
        calls.append(1)
        return driver

    monkeypatch.setattr("clickhouse_connect.get_client", _get)
    client = build_client(_config(), _secrets())
    assert list(client.query("SELECT 1")) == [[1], [2]]
    client.command("SELECT 2")  # reuses the already-open driver
    assert len(calls) == 1
    client.close()
    client.close()  # idempotent


def test_query_wraps_a_driver_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeDriver):
        def query(self, statement: str) -> Any:
            raise RuntimeError("driver failure")

    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _Boom())
    client = build_client(_config(), _secrets())
    with pytest.raises(StorageError) as captured:
        client.query("SELECT 1")
    assert captured.value.code == "MH_STORAGE_CLIENT"
