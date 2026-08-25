from __future__ import annotations

from milhouse.core.errors import MilhouseValueError


class SpoolError(MilhouseValueError):
    """A fixed, privacy-safe spool failure carrying only a stable code and static message.

    Every spool failure is raised outside any active exception handler, so no filesystem, canonical,
    or record detail reaches the error's cause, context, args, or traceback. The stable
    ``MH_SPOOL_*`` codes are the only machine surface.
    """
