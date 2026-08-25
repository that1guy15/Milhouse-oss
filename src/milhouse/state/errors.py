from __future__ import annotations

from milhouse.core.errors import MilhouseValueError


class StateError(MilhouseValueError):
    """A fixed, privacy-safe control-state failure carrying only a stable code and static message.

    Every control-state failure is raised outside any active exception handler, so no SQLite,
    filesystem, or caller detail reaches the error's cause, context, args, or traceback. The stable
    ``MH_STATE_*`` codes are the only machine surface; the messages are static developer text.
    """
