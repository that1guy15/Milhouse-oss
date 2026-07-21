"""Stable, value-free configuration errors shared by config boundary modules."""

from __future__ import annotations

from milhouse.core.errors import MilhouseError


class ConfigError(MilhouseError):
    """A stable configuration failure that never requires rendering an input value."""


__all__ = ["ConfigError"]
