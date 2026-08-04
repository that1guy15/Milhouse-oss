"""Offline security lint of the reference ClickHouse compose + users.d (W04, ADR 0005).

Statically verifies the hardening contract without starting a container: loopback-only ports, an
exact digest pin on the 26.3 line, a dedicated non-empty credential from the environment (no
committed secret and no unauthenticated `default` account), the mounted users.d default-account
lock, a health check, and resource guidance.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree import ElementTree

import yaml

_OPS = Path(__file__).resolve().parents[2] / "ops" / "clickhouse"


def _service() -> dict[str, Any]:
    compose = yaml.safe_load((_OPS / "docker-compose.yml").read_text(encoding="utf-8"))
    return compose["services"]["clickhouse"]


def test_ports_are_bound_to_loopback_only() -> None:
    for published in _service()["ports"]:
        assert str(published).startswith("127.0.0.1:"), published


def test_image_is_digest_pinned_on_the_reference_line() -> None:
    image = _service()["image"]
    assert image.startswith("clickhouse/clickhouse-server:26.3@sha256:")
    assert len(image.split("@sha256:")[1]) == 64


def test_no_unauthenticated_or_default_account() -> None:
    environment = _service()["environment"]
    user = str(environment.get("CLICKHOUSE_USER", ""))
    password = str(environment.get("CLICKHOUSE_PASSWORD", ""))
    assert user.startswith("${")  # dedicated user resolved from the environment
    assert "default" not in user.lower()
    assert password.startswith("${") and password != ""  # from env, never a committed literal
    assert str(environment.get("CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT")) == "0"


def test_users_d_is_mounted_read_only_and_locks_default() -> None:
    volumes = [str(volume) for volume in _service()["volumes"]]
    assert any("users.d" in volume and volume.endswith(":ro") for volume in volumes)

    # Parse the XML and assert the built-in `default` account is EFFECTIVELY denied — not merely
    # that a `replace="replace"` string is present. A regression that re-opens `default` (a routable
    # <ip>/<host>, a dropped deny, or a missing block) must fail this guard.
    root = ElementTree.fromstring(
        (_OPS / "users.d" / "milhouse-users.xml").read_text(encoding="utf-8")
    )
    default = root.find("./users/default")
    assert default is not None, "users.d must lock the built-in default account"
    networks = default.find("./networks")
    assert networks is not None and networks.get("replace") == "replace"
    hosts = networks.findall("./host")
    assert len(hosts) == 1 and (hosts[0].text or "").endswith(".invalid")
    # No routable allow-rule may coexist with the deny host.
    assert networks.findall("./ip") == []
    assert networks.findall("./host_regexp") == []
    access_management = default.find("./access_management")
    assert access_management is not None and (access_management.text or "").strip() == "0"


def test_healthcheck_and_resource_guidance_present() -> None:
    service = _service()
    assert "healthcheck" in service
    assert "ulimits" in service or "deploy" in service


def test_env_example_commits_no_secret() -> None:
    for line in (_OPS / ".env.example").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("MILHOUSE_") and "PASSWORD" in stripped:
            assert stripped.endswith("="), stripped
