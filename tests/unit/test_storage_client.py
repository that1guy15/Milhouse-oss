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
        self.inserts: list[dict[str, Any]] = []

    def command(self, statement: str) -> None:
        self.commands.append(statement)

    def query(self, statement: str, *, parameters: Any = None) -> Any:
        raise AssertionError("not used")

    def insert(
        self, *, table: str, data: Any, column_names: Any, database: str, settings: Any = None
    ) -> None:
        self.inserts.append(
            {
                "table": table,
                "data": data,
                "column_names": column_names,
                "database": database,
                "settings": settings,
            }
        )

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
        def query(self, statement: str, *, parameters: Any = None) -> Any:
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
        def query(self, statement: str, *, parameters: Any = None) -> Any:
            raise RuntimeError("driver failure")

    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _Boom())
    client = build_client(_config(), _secrets())
    with pytest.raises(StorageError) as captured:
        client.query("SELECT 1")
    assert captured.value.code == "MH_STORAGE_CLIENT"


def test_query_forwards_bound_parameters_to_the_driver(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Any] = []

    class _Result:
        def __init__(self) -> None:
            self.result_rows = [["ok"]]

    class _Driver(_FakeDriver):
        def query(self, statement: str, *, parameters: Any = None) -> Any:
            seen.append(parameters)
            return _Result()

    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _Driver())
    client = build_client(_config(), _secrets())
    rows = client.query("SELECT 1 WHERE x = {x:String}", parameters={"x": "value"})
    assert list(rows) == [["ok"]]
    assert seen == [{"x": "value"}]


def test_insert_transmits_rows_as_native_column_data(monkeypatch: pytest.MonkeyPatch) -> None:
    driver = _FakeDriver()
    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: driver)
    client = build_client(_config(), _secrets())

    client.insert("milhouse", "records", [("a", 1), ("b", 2)], column_names=("name", "n"))

    assert driver.inserts == [
        {
            "table": "records",
            "data": [["a", 1], ["b", 2]],
            "column_names": ["name", "n"],
            "database": "milhouse",
            "settings": {"async_insert": 0, "wait_for_async_insert": 1},
        }
    ]


def test_insert_pins_synchronous_insert_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    # Synchronous, fully-acknowledged inserts (async_insert=0, wait_for_async_insert=1) are pinned
    # so an acknowledged row is durably visible before the commit barrier releases — the migrate
    # fence relies on it. Prove the client forwards them, overriding any server async default.
    driver = _FakeDriver()
    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: driver)
    client = build_client(_config(), _secrets())

    client.insert("milhouse", "records", [("a", 1)], column_names=("name", "n"))

    assert driver.inserts[0]["settings"] == {"async_insert": 0, "wait_for_async_insert": 1}


def test_insert_skips_an_empty_batch_without_opening_a_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(
        "clickhouse_connect.get_client", lambda **kw: calls.append(1) or _FakeDriver()
    )
    client = build_client(_config(), _secrets())
    client.insert("milhouse", "records", [], column_names=("name",))
    assert calls == []  # an empty batch is a no-op; the driver is never even constructed


def test_insert_wraps_a_driver_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeDriver):
        def insert(
            self, *, table: str, data: Any, column_names: Any, database: str, settings: Any = None
        ) -> None:
            raise RuntimeError("driver failure")

    monkeypatch.setattr("clickhouse_connect.get_client", lambda **kw: _Boom())
    client = build_client(_config(), _secrets())
    with pytest.raises(StorageError) as captured:
        client.insert("milhouse", "records", [("a",)], column_names=("name",))
    assert captured.value.code == "MH_STORAGE_CLIENT"
