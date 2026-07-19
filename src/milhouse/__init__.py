"""Milhouse OSS package."""

from typing import Final

__all__ = ["__version__"]

# The pre-alpha package version has one source inside the import package. CLI
# output imports this value instead of maintaining a second copy.
__version__: Final = "0.1.0a0"
