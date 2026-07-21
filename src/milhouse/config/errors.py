"""Stable, value-free configuration errors shared by config boundary modules."""

from __future__ import annotations


class ConfigError(Exception):
    """A stable configuration failure that never requires rendering an input value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


__all__ = ["ConfigError"]
