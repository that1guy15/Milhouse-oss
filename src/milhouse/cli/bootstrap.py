"""Config-driven ``init`` and ``health`` bootstrap for the Milhouse CLI.

First runnable product slice (a preparatory vertical on the passed W02 config/identity and W03
spool/state foundations; it does not claim the W05/W06 gates). ``initialize`` creates the state-root
layout under restrictive permissions, applies the control-plane schema, and generates a durable
non-secret installation identity; ``health`` reports whether an initialized install is usable. Both
are local, spool-only, and credential-free — no network, no secret resolution, no provider calls.

The installation identity here is the record-identity ``mh_in1_`` UUID used in canonical record
derivation (plan section 4.2), persisted as an owner-only file in the control directory. When the
validated config is supplied (the ``init`` command passes it), ``initialize`` ALSO provisions the
keyed pseudonym key of plan section 4.7 that the runtime redactor requires — created once,
owner-only (0600), and never rotated on a re-run — by reusing the ``privacy.keys`` primitives
exactly. Callers that do not need the key (the spool-only demo) omit the config and never touch it.
Key material is never logged, echoed, or returned: only whether a key was provisioned.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from milhouse.config import RuntimePaths
from milhouse.config._models import MilhouseConfig
from milhouse.config.filesystem import (
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
    open_regular_file_no_follow,
)
from milhouse.privacy.keys import (
    PseudonymKeyCommitUncertain,
    _validate_key_metadata,
    create_pseudonym_key,
    recover_pseudonym_key_creation,
)
from milhouse.privacy.pseudonym import PrivacyError
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
    #: Whether this pass created the keyed pseudonym key. Always ``False`` when ``initialize`` was
    #: called without a config (the credential-free callers that never touch the key).
    pseudonym_key_created: bool = False

    @property
    def already_initialized(self) -> bool:
        """Whether the pass changed nothing durable (fully idempotent re-run)."""

        return (
            not self.created_directories
            and not self.installation_id_created
            and not self.pseudonym_key_created
        )


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


def barrier_path(paths: RuntimePaths) -> Path:
    """Return the single global commit-lock path (the control dir's ``commit.lock``).

    The sole constructor of the :class:`GlobalCommitBarrier` path across the CLI, so every writer
    (``collect``, ``storage`` export/migrate/backup/restore, ``demo``, ``init``) acquires the SAME
    lock file. A divergent join at any one site would silently break the single-writer exclusion.
    """

    return _control_dir(paths) / BARRIER_NAME


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


def _ensure_private_key_parent(paths: RuntimePaths) -> None:
    """Ensure every directory from STATE_ROOT down to the pseudonym key's parent is owner-only.

    A non-default nested ``identity.pseudonym_key_path`` may put the key beneath directories the
    managed set does not cover. Each intermediate level is created individually (0700) rather than
    with ``mkdir(parents=True)`` in one call, because that would create the intermediates with the
    umask default and tighten only the leaf. ``resolve_runtime_paths`` guarantees the key stays a
    strict descendant of STATE_ROOT, so the upward walk terminates at STATE_ROOT.
    """

    pending: list[Path] = []
    current = paths.pseudonym_key.parent
    while True:
        pending.append(current)
        if current == paths.state_root or current == current.parent:
            break
        current = current.parent
    for directory in reversed(pending):  # shallowest first: each level's parent already exists
        _ensure_private_directory(directory)


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


def _ensure_pseudonym_key(config: MilhouseConfig, paths: RuntimePaths) -> bool:
    """Provision the keyed pseudonym key iff absent; recover a commit-uncertain publish. Idempotent.

    Reuses the ``privacy.keys`` primitives EXACTLY: ``create_pseudonym_key`` writes a fresh
    owner-only (0600) key and refuses to overwrite an existing path, so a present key is left
    untouched (never rotated) and reported as ``False``. A commit-uncertain publication is durably
    adopted through ``recover_pseudonym_key_creation`` using the non-secret key id it carries; a
    still-uncertain or otherwise failed provision fails closed with a fixed code. The returned
    :class:`Pseudonymizer` is deliberately discarded — this function NEVER logs, echoes, or returns
    key material, only whether a key was created.
    """

    try:
        create_pseudonym_key(config, paths)
    except PseudonymKeyCommitUncertain as uncertain:
        # The key bytes reached disk but their durability was uncertain: verify by non-secret key id
        # (``mh_pk1_...`` -- not key material) and fsync the parent. A still-uncertain outcome fails
        # closed rather than leaving a possibly-unrecoverable key silently in place.
        try:
            recover_pseudonym_key_creation(config, paths, expected_key_id=uncertain.key_id)
        except PrivacyError as error:
            raise BootstrapError(
                "MH_INIT_PSEUDONYM_KEY",
                "the pseudonym key could not be durably provisioned",
            ) from error
        return True
    except PrivacyError as error:
        if error.code == "MH_PRIVACY_KEY_EXISTS":
            # Idempotent: a present key is never rotated or overwritten on a re-run.
            return False
        raise BootstrapError(
            "MH_INIT_PSEUDONYM_KEY",
            "the pseudonym key could not be provisioned",
        ) from error
    return True


def initialize(
    paths: RuntimePaths, *, now: datetime, config: MilhouseConfig | None = None
) -> InitReport:
    """Idempotently create the state-root layout, apply the schema, and establish identity.

    Creates ``state_root`` and its ``control``/``spool``/``reports``/``logs``/``backups`` children
    (0700), opens the control database and applies every unapplied migration under the commit
    barrier, and generates the installation id if absent. When ``config`` is supplied (the ``init``
    command passes the validated config), it ALSO provisions the keyed pseudonym key the runtime
    redactor requires, once and owner-only, reusing the ``privacy.keys`` primitives. Re-running
    changes nothing durable — the key is never rotated once present.
    """

    created: list[str] = []
    for label, directory in _managed_directories(paths):
        if _ensure_private_directory(directory):
            created.append(label)

    database = open_control_database(database_path(paths))
    try:
        barrier = GlobalCommitBarrier(barrier_path(paths))
        version = initialize_control_state(database, barrier=barrier, applied_at=now)
    finally:
        database.close()

    installation_created = _ensure_installation_id(paths)
    # The pseudonym key is provisioned only when the validated config is available: its secure
    # creation is bound to that config's resolved runtime generation, and credential-free callers
    # (the spool-only demo) never need it.
    pseudonym_key_created = False
    if config is not None:
        # Ensure the key's owner-only (0700) parent chain exists first, or the secure key creation
        # would fail with an opaque parent-missing error for a non-default nested key path.
        _ensure_private_key_parent(paths)
        pseudonym_key_created = _ensure_pseudonym_key(config, paths)
    return InitReport(
        created_directories=tuple(created),
        schema_version=version,
        installation_id_created=installation_created,
        pseudonym_key_created=pseudonym_key_created,
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


def _pseudonym_key_check(paths: RuntimePaths) -> HealthCheck:
    """Report the pseudonym key's health, VALIDATED the way ``collect``'s key load validates it.

    A mere presence probe would call an install whose key is present-but-corrupt (wrong
    mode/size/owner/nlink, an unsafe parent, or a non-regular file) "healthy" while ``collect run``
    rejects it with a precise ``MH_PRIVACY_KEY_*`` code, so this opens the key no-follow beneath an
    owner-only parent (as :func:`~milhouse.privacy.keys.load_pseudonym_key` does) and runs the
    shared :func:`~milhouse.privacy.keys._validate_key_metadata` over the ``os.fstat`` METADATA
    only. It is privacy-safe: it inspects fstat metadata ONLY and NEVER reads, loads, logs, or
    returns key material. Absent → ``missing``; present but failing validation → ``present but
    invalid``.
    """

    try:
        opened = open_regular_file_no_follow(paths.pseudonym_key, require_private_parent=True)
    except SecureFileError as error:
        detail = (
            "missing (run milhouse init)"
            if error.kind is SecureFileErrorKind.NOT_FOUND
            else "present but invalid (run milhouse init)"
        )
        return HealthCheck("pseudonym_key", False, detail)
    descriptor = opened.descriptor
    try:
        _validate_key_metadata(os.fstat(descriptor))
    except (PrivacyError, OSError):
        return HealthCheck("pseudonym_key", False, "present but invalid (run milhouse init)")
    finally:
        try:
            os.close(descriptor)
        except OSError:  # pragma: no cover - defensive: close of our own fd
            pass
    return HealthCheck("pseudonym_key", True, "present")


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

    # The runtime redactor -- and therefore ``collect run`` -- hard-requires a VALID pseudonym key,
    # so an install whose key is missing or corrupt is NOT usable even though its directories,
    # schema, and identity are sound. Validate it (metadata only) so ``health``/``doctor`` no longer
    # call such an install healthy while ``collect run`` fails "run milhouse init first".
    checks.append(_pseudonym_key_check(paths))
    return HealthReport(checks=tuple(checks))
