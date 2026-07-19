"""Root Click command for the Milhouse CLI."""

from __future__ import annotations

import click

from milhouse import __version__


@click.group(
    name="milhouse",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
@click.version_option(version=__version__, prog_name="milhouse")
def main() -> None:
    """Local-first observability and verified feedback loops (pre-alpha)."""
