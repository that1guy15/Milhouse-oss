"""Verify the ClickHouse migrations ship as importable package data (W04)."""

from __future__ import annotations

import tomllib
from importlib import resources
from pathlib import Path

_MIGRATION_FILES = (
    "0001_core.sql",
    "0002_records.sql",
    "0003_feedback.sql",
    "0004_views.sql",
    "0005_feedback_transition_dedup.sql",
)


def test_migrations_are_readable_via_importlib_resources() -> None:
    root = resources.files("milhouse.storage.migrations")
    for filename in _MIGRATION_FILES:
        text = root.joinpath(filename).read_text(encoding="utf-8")
        assert text.strip()


def test_pyproject_ships_the_migrations_as_package_data() -> None:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    package_data = data["tool"]["setuptools"]["package-data"]
    assert package_data.get("milhouse.storage.migrations") == ["*.sql"]
