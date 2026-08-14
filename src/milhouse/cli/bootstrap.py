"""Config-driven ``init`` and ``health`` bootstrap for the Milhouse CLI.

First runnable product slice (a preparatory vertical on the passed W02 config/identity and W03
spool/state foundations; it does not claim the W05/W06 gates). ``initialize`` creates the state-root
layout under restrictive permissions, applies the control-plane schema, and generates a durable
non-secret installation identity; ``health`` reports whether an initialized install is usable. Both
are local, spool-only, and credential-free — no network, no secret resolution, no provider calls.

The installation identity here is the record-identity ``mh_in1_`` UUID used in canonical record
derivation (plan section 4.2), persisted as an owner-only file in the control directory. It is
distinct from the keyed pseudonym-key lifecycle of plan section 4.7, which amendment A09 keeps
deferred; this slice never creates or reads that key.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from milhouse.config import RuntimePaths
from milhouse.config.filesystem import (
    SecureFileError,
    create_regular_file_no_follow,
    open_regular_file_no_follow,
)
from milhouse.state import (
    GlobalCommitBarrier,
    initialize_control_state,
    open_control_database,
    schema_version,
)

CONTROL_DIRNAME = "control"
DATABASE_NAME = "milhouse.sqlite3"
BARRIER_NAME = "commit.lock"
INSTALLATION_ID_NAME = "installation.id"
#: The current applied control-schema version (see ``state/schema.py``; W05 appended migration 11,
#: the canary alert-rule state table).
EXPECTED_SCHEMA_VERSION = 11

_DIR_MODE = 0o700
_ID_FILE_MODE = 0o600
_MAX_ID_BYTES = 64
_INSTALLATION_ID_PATTERN = re.compile(
    r"mh_in1_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}", flags=re.ASCII
)


class BootstrapError(Exception):
    """A stable, privacy-safe bootstrap failure carrying a fixed code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True, slots=True)
class InitReport:
    """The outcome of one ``initialize`` pass over a config's runtime paths."""

    created_directories: tuple[str, ...]
    schema_version: int
    installation_id_created: bool

    @property
    def already_initialized(self) -> bool:
        """Whether the pass changed nothing durable (fully idempotent re-run)."""

        return not self.created_directories and not self.installation_id_created


@dataclass(frozen=True, slots=True)
class HealthCheck:
    """One named health assertion and its privacy-safe outcome."""

    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class HealthReport:
    """The aggregate result of a ``health`` pass. ``status`` is ``healthy`` or ``unhealthy``."""

    checks: tuple[HealthCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.ok for check in self.checks)

    @property
    def status(self) -> str:
        return "healthy" if self.healthy else "unhealthy"


def _control_dir(paths: RuntimePaths) -> Path:
    return paths.state_root / CONTROL_DIRNAME


def database_path(paths: RuntimePaths) -> Path:
    return _control_dir(paths) / DATABASE_NAME


def _installation_id_path(paths: RuntimePaths) -> Path:
    return _control_dir(paths) / INSTALLATION_ID_NAME


def _managed_directories(paths: RuntimePaths) -> tuple[tuple[str, Path], ...]:
    return (
        ("state_root", paths.state_root),
        (CONTROL_DIRNAME, _control_dir(paths)),
        ("spool", paths.spool),
        ("reports", paths.reports),
        ("logs", paths.logs),
        ("backups", paths.backups),
    )


def _ensure_private_directory(path: Path) -> bool:
    """Create ``path`` (0700) if absent; always tighten its mode. Returns whether it was created."""

    created = not path.exists()
    try:
        path.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        os.chmod(path, _DIR_MODE)
    except OSError as error:
        raise BootstrapError("MH_INIT_DIR", "a state directory could not be created") from error
    return created


def _generate_installation_id() -> str:
    # uuid4().hex is exactly the mh_in1_ payload shape (version nibble 4, variant [89ab]).
    return "mh_in1_" + uuid.uuid4().hex


def read_installation_id(paths: RuntimePaths) -> str | None:
    """Return the persisted installation id, or ``None`` if absent/unreadable/malformed."""

    try:
        opened = open_regular_file_no_follow(_installation_id_path(paths))
    except SecureFileError:
        return None
    descriptor = opened.descriptor
    try:
        raw = os.read(descriptor, _MAX_ID_BYTES + 1)
    except OSError:  # pragma: no cover - defensive: an open fd rarely fails a bounded read
        return None
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive: close of our own fd
            pass
    if len(raw) > _MAX_ID_BYTES:
        return None
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return value if _INSTALLATION_ID_PATTERN.fullmatch(value) is not None else None


def _ensure_installation_id(paths: RuntimePaths) -> bool:
    """Persist a fresh installation id iff none is present. Returns whether one was created."""

    if read_installation_id(paths) is not None:
        return False
    new_id = _generate_installation_id()
    try:
        create_regular_file_no_follow(
            _installation_id_path(paths),
            new_id.encode("ascii"),
            mode=_ID_FILE_MODE,
            require_private_parent=True,
        )
    except SecureFileError as error:  # pragma: no cover - defensive: concurrent-init / IO race
        # An existing id lost a race with a concurrent init: treat a present valid id as success.
        if read_installation_id(paths) is not None:
            return False
        raise BootstrapError(
            "MH_INIT_IDENTITY", "the installation identity could not be established"
        ) from error
    return True


def initialize(paths: RuntimePaths, *, now: datetime) -> InitReport:
    """Idempotently create the state-root layout, apply the schema, and establish identity.

    Creates ``state_root`` and its ``control``/``spool``/``reports``/``logs``/``backups`` children
    (0700), opens the control database and applies every unapplied migration under the commit
    barrier, and generates the installation id if absent. Re-running changes nothing durable.
    """

    created: list[str] = []
    for label, directory in _managed_directories(paths):
        if _ensure_private_directory(directory):
            created.append(label)

    database = open_control_database(database_path(paths))
    try:
        barrier = GlobalCommitBarrier(_control_dir(paths) / BARRIER_NAME)
        version = initialize_control_state(database, barrier=barrier, applied_at=now)
    finally:
        database.close()

    installation_created = _ensure_installation_id(paths)
    return InitReport(
        created_directories=tuple(created),
        schema_version=version,
        installation_id_created=installation_created,
    )


def _database_check(paths: RuntimePaths) -> HealthCheck:
    """Report the control-database health without mutating or raising on a bad database."""

    if not database_path(paths).is_file():
        return HealthCheck("control_database", False, "missing (run milhouse init)")
    try:
        database = open_control_database(database_path(paths))
        try:
            version = schema_version(database)
        finally:
            database.close()
    except Exception:  # pragma: no cover - defensive: a health probe reports, never raises
        return HealthCheck("control_database", False, "unreadable")
    ok = version == EXPECTED_SCHEMA_VERSION
    detail = f"schema {version}" if ok else f"schema {version}, expected {EXPECTED_SCHEMA_VERSION}"
    return HealthCheck("control_database", ok, detail)


def health(paths: RuntimePaths, *, now: datetime) -> HealthReport:
    """Report whether an initialized install is usable, without mutating anything."""

    checks: list[HealthCheck] = []
    for label, directory in _managed_directories(paths):
        present = directory.is_dir()
        checks.append(
            HealthCheck(
                name=f"directory:{label}",
                ok=present,
                detail="present" if present else "missing (run milhouse init)",
            )
        )

    checks.append(_database_check(paths))

    identity_present = read_installation_id(paths) is not None
    checks.append(
        HealthCheck(
            "installation_identity",
            identity_present,
            "established" if identity_present else "missing (run milhouse init)",
        )
    )
    return HealthReport(checks=tuple(checks))
