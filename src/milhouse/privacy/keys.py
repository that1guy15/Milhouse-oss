"""Secure creation and loading of installation-local pseudonym key material."""

from __future__ import annotations

import hmac
import os
import re
import secrets
import stat
from collections.abc import Callable
from pathlib import Path

from milhouse.config._models import MilhouseConfig
from milhouse.config.filesystem import (
    FileSelection,
    SecureFileError,
    SecureFileErrorKind,
    create_regular_file_no_follow,
    inspect_regular_file_no_follow,
    open_regular_file_no_follow,
    sync_parent_directory_no_follow,
)
from milhouse.config.loader import verify_config_generation
from milhouse.config.paths import RuntimePaths, verify_runtime_path_generation
from milhouse.privacy.pseudonym import (
    PSEUDONYM_KEY_BYTES,
    PrivacyError,
    Pseudonymizer,
    validate_pseudonym_epoch,
)

PSEUDONYM_KEY_MODE = 0o600

_KEY_ID_PATTERN = re.compile(r"^mh_pk1_[0-9a-f]{16}$")


class PseudonymKeyCommitUncertain(PrivacyError):
    """A published key needs explicit identity-checked durability recovery."""

    __slots__ = ("__key_id",)

    def __init__(self, key_id: str) -> None:
        super().__init__(
            "MH_PRIVACY_KEY_COMMIT_UNCERTAIN",
            "pseudonym key publication requires explicit recovery",
        )
        self.__key_id = key_id

    @property
    def key_id(self) -> str:
        """Return the non-secret key ID required by the recovery operation."""

        return self.__key_id

    def __repr__(self) -> str:
        return "PseudonymKeyCommitUncertain(recovery_required=True)"


def _key_error(code: str, message: str) -> PrivacyError:
    return PrivacyError(code, message)


def _bound_key_path(config: MilhouseConfig, paths: RuntimePaths) -> Path:
    """Return the key path only when it matches one securely loaded runtime generation."""

    if getattr(os, "O_NOFOLLOW", 0) == 0:
        raise _key_error(
            "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED",
            "safe pseudonym key filesystem operations are unavailable",
        )
    if not isinstance(config, MilhouseConfig) or not isinstance(paths, RuntimePaths):
        raise _key_error(
            "MH_PRIVACY_KEY_BINDING",
            "pseudonym key access requires validated runtime paths",
        )
    try:
        selection = verify_config_generation(config, paths.config_selection)
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_CONFIG",
            "validated configuration changed before pseudonym key access",
        ) from None

    try:
        state_root = Path(os.path.normpath(os.fspath(paths.state_root)))
        key_path = Path(os.path.normpath(os.fspath(paths.pseudonym_key)))
        config_file = Path(os.path.normpath(os.fspath(paths.config_file)))
        config_dir = Path(os.path.normpath(os.fspath(paths.config_dir)))
    except (OSError, TypeError, ValueError):
        raise _key_error(
            "MH_PRIVACY_KEY_BINDING",
            "pseudonym key runtime paths are invalid",
        ) from None

    if (
        not state_root.is_absolute()
        or state_root == Path(state_root.anchor)
        or not key_path.is_absolute()
        or config_file != selection.path
        or config_dir != config_file.parent
    ):
        raise _key_error(
            "MH_PRIVACY_KEY_BINDING",
            "pseudonym key runtime paths do not match the selected configuration",
        )
    try:
        relative_key = key_path.relative_to(state_root)
    except ValueError:
        raise _key_error(
            "MH_PRIVACY_KEY_ESCAPE",
            "pseudonym key must remain beneath STATE_ROOT",
        ) from None
    if not relative_key.parts:
        raise _key_error(
            "MH_PRIVACY_KEY_ESCAPE",
            "pseudonym key must remain beneath STATE_ROOT",
        )

    configured = Path(config.identity.pseudonym_key_path)
    expected = configured if configured.is_absolute() else state_root / configured
    expected = Path(os.path.normpath(os.fspath(expected)))
    try:
        expected.relative_to(state_root)
    except ValueError:
        raise _key_error(
            "MH_PRIVACY_KEY_ESCAPE",
            "configured pseudonym key must remain beneath STATE_ROOT",
        ) from None
    if key_path != expected:
        raise _key_error(
            "MH_PRIVACY_KEY_BINDING",
            "pseudonym key path does not match the selected configuration",
        )

    try:
        verify_runtime_path_generation(paths)
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_BINDING",
            "runtime paths changed after their validated resolution",
        ) from None
    try:
        verify_config_generation(config, selection)
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_CONFIG",
            "validated configuration changed before pseudonym key access",
        ) from None
    return key_path


def _create_error(error: SecureFileError, *, key_id: str) -> PrivacyError:
    if error.kind is SecureFileErrorKind.ACCESS_CONTROL_UNSAFE:
        return _key_error(
            "MH_PRIVACY_KEY_ACL",
            "pseudonym key must not have extended access controls",
        )
    if error.kind is SecureFileErrorKind.ALREADY_EXISTS:
        return _key_error(
            "MH_PRIVACY_KEY_EXISTS",
            "pseudonym key already exists and will not be overwritten",
        )
    if error.kind is SecureFileErrorKind.NOT_FOUND:
        return _key_error(
            "MH_PRIVACY_KEY_PARENT_MISSING",
            "pseudonym key parent directory does not exist",
        )
    if error.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED:
        return _key_error(
            "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED",
            "safe pseudonym key creation is unavailable",
        )
    if error.kind is SecureFileErrorKind.PARENT_UNSAFE:
        return _key_error(
            "MH_PRIVACY_KEY_PARENT_UNSAFE",
            "pseudonym key parent directory must be owner-only",
        )
    if error.kind is SecureFileErrorKind.COMMIT_UNCERTAIN:
        return PseudonymKeyCommitUncertain(key_id)
    if error.kind is SecureFileErrorKind.CLEANUP_FAILED:
        return _key_error(
            "MH_PRIVACY_KEY_CLEANUP",
            "failed pseudonym key creation could not be safely cleaned up",
        )
    if error.kind is SecureFileErrorKind.PERMISSION_FAILED:
        return _key_error(
            "MH_PRIVACY_KEY_PERMISSION",
            "pseudonym key permissions could not be restricted",
        )
    if error.kind is SecureFileErrorKind.SYNC_FAILED:
        return _key_error(
            "MH_PRIVACY_KEY_SYNC",
            "pseudonym key could not be durably synchronized",
        )
    if error.kind is SecureFileErrorKind.WRITE_FAILED:
        return _key_error(
            "MH_PRIVACY_KEY_WRITE",
            "pseudonym key could not be completely written",
        )
    if error.kind is SecureFileErrorKind.CHANGED:
        return _key_error(
            "MH_PRIVACY_KEY_CHANGED",
            "pseudonym key path changed during creation",
        )
    return _key_error(
        "MH_PRIVACY_KEY_CREATE",
        "pseudonym key could not be safely created",
    )


def _read_error(error: SecureFileError) -> PrivacyError:
    if error.kind is SecureFileErrorKind.ACCESS_CONTROL_UNSAFE:
        return _key_error(
            "MH_PRIVACY_KEY_ACL",
            "pseudonym key must not have extended access controls",
        )
    if error.kind is SecureFileErrorKind.NOT_FOUND:
        return _key_error("MH_PRIVACY_KEY_NOT_FOUND", "pseudonym key was not found")
    if error.kind is SecureFileErrorKind.NOT_REGULAR:
        return _key_error(
            "MH_PRIVACY_KEY_TYPE",
            "pseudonym key must be a regular non-symlink file",
        )
    if error.kind is SecureFileErrorKind.SECURITY_UNSUPPORTED:
        return _key_error(
            "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED",
            "safe pseudonym key loading is unavailable",
        )
    if error.kind is SecureFileErrorKind.PARENT_UNSAFE:
        return _key_error(
            "MH_PRIVACY_KEY_PARENT_UNSAFE",
            "pseudonym key parent directory must be owner-only",
        )
    return _key_error("MH_PRIVACY_KEY_READ", "pseudonym key could not be safely read")


def _metadata_coordinates(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_nlink,
    )


def _validate_key_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise _key_error(
            "MH_PRIVACY_KEY_TYPE",
            "pseudonym key must be a regular non-symlink file",
        )
    if metadata.st_size != PSEUDONYM_KEY_BYTES:
        raise _key_error(
            "MH_PRIVACY_KEY_SIZE",
            f"pseudonym key must contain exactly {PSEUDONYM_KEY_BYTES} bytes",
        )
    if stat.S_IMODE(metadata.st_mode) != PSEUDONYM_KEY_MODE:
        raise _key_error(
            "MH_PRIVACY_KEY_MODE",
            "pseudonym key must have owner-only read and write permissions",
        )
    effective_user_id = getattr(os, "geteuid", None)
    if effective_user_id is None:
        raise _key_error(
            "MH_PRIVACY_KEY_SECURITY_UNSUPPORTED",
            "pseudonym key ownership checks are unavailable",
        )
    if metadata.st_uid != effective_user_id():
        raise _key_error(
            "MH_PRIVACY_KEY_OWNER",
            "pseudonym key must be owned by the current user",
        )
    if metadata.st_nlink != 1:
        raise _key_error(
            "MH_PRIVACY_KEY_LINKS",
            "pseudonym key must have exactly one filesystem link",
        )


def _read_key_material(path: Path) -> bytes:
    try:
        opened = open_regular_file_no_follow(path, require_private_parent=True)
    except SecureFileError as error:
        raise _read_error(error) from None

    descriptor = opened.descriptor
    failure: PrivacyError | None = None
    raw = b""
    after_read: os.stat_result | None = None
    try:
        before_read = os.fstat(descriptor)
        _validate_key_metadata(before_read)
        chunks: list[bytes] = []
        remaining = PSEUDONYM_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after_read = os.fstat(descriptor)
        _validate_key_metadata(after_read)
        if _metadata_coordinates(before_read) != _metadata_coordinates(after_read):
            raise _key_error(
                "MH_PRIVACY_KEY_CHANGED",
                "pseudonym key changed while it was being read",
            )
    except PrivacyError as error:
        failure = error
    except (OSError, ValueError):
        failure = _key_error("MH_PRIVACY_KEY_READ", "pseudonym key could not be safely read")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            failure = _key_error(
                "MH_PRIVACY_KEY_READ",
                "pseudonym key could not be safely read",
            )

    if failure is not None:
        raise failure from None
    if len(raw) != PSEUDONYM_KEY_BYTES or after_read is None:
        raise _key_error(
            "MH_PRIVACY_KEY_SIZE",
            f"pseudonym key must contain exactly {PSEUDONYM_KEY_BYTES} bytes",
        )

    try:
        current = inspect_regular_file_no_follow(path, require_private_parent=True)
    except SecureFileError:
        raise _key_error(
            "MH_PRIVACY_KEY_CHANGED",
            "pseudonym key path changed while it was being read",
        ) from None
    expected_selection = FileSelection(
        path=opened.path,
        parent_identity=opened.parent_identity,
        snapshot=opened.snapshot,
    )
    if current != expected_selection:
        raise _key_error(
            "MH_PRIVACY_KEY_CHANGED",
            "pseudonym key path changed while it was being read",
        )
    return raw


def create_pseudonym_key(
    config: MilhouseConfig,
    paths: RuntimePaths,
    *,
    epoch: int = 1,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> Pseudonymizer:
    """Create one new key without overwriting any existing path."""

    validate_pseudonym_epoch(epoch)
    try:
        key = random_bytes(PSEUDONYM_KEY_BYTES)
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_RANDOM",
            "pseudonym key entropy generation failed",
        ) from None
    if type(key) is not bytes or len(key) != PSEUDONYM_KEY_BYTES:
        raise _key_error(
            "MH_PRIVACY_KEY_RANDOM",
            "pseudonym key entropy generation returned an invalid result",
        )
    pseudonymizer = Pseudonymizer(key, epoch=epoch)
    key_path = _bound_key_path(config, paths)

    def verify_before_publish() -> None:
        if _bound_key_path(config, paths) != key_path:
            raise _key_error(
                "MH_PRIVACY_KEY_BINDING",
                "runtime paths changed before pseudonym key publication",
            )

    try:
        create_regular_file_no_follow(
            key_path,
            key,
            mode=PSEUDONYM_KEY_MODE,
            before_publish=verify_before_publish,
            require_private_parent=True,
        )
    except SecureFileError as error:
        raise _create_error(error, key_id=pseudonymizer.key_id) from None
    except PrivacyError:
        raise
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_CREATE",
            "pseudonym key could not be safely created",
        ) from None
    return pseudonymizer


def load_pseudonym_key(
    config: MilhouseConfig,
    paths: RuntimePaths,
    *,
    epoch: int = 1,
    expected_key_id: str | None = None,
) -> Pseudonymizer:
    """Load one unchanged owner-only key and optionally verify its non-secret key ID."""

    validate_pseudonym_epoch(epoch)
    if expected_key_id is not None and (
        type(expected_key_id) is not str or _KEY_ID_PATTERN.fullmatch(expected_key_id) is None
    ):
        raise _key_error(
            "MH_PRIVACY_KEY_ID",
            "expected pseudonym key ID is invalid",
        )
    key_path = _bound_key_path(config, paths)
    try:
        key = _read_key_material(key_path)
    except PrivacyError:
        raise
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_READ",
            "pseudonym key could not be safely read",
        ) from None
    try:
        verify_config_generation(config, paths.config_selection)
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_CONFIG",
            "validated configuration changed during pseudonym key loading",
        ) from None
    pseudonymizer = Pseudonymizer(key, epoch=epoch)
    if expected_key_id is not None and not hmac.compare_digest(
        pseudonymizer.key_id,
        expected_key_id,
    ):
        raise _key_error(
            "MH_PRIVACY_KEY_ID_MISMATCH",
            "pseudonym key does not match the expected key ID",
        )
    return pseudonymizer


def recover_pseudonym_key_creation(
    config: MilhouseConfig,
    paths: RuntimePaths,
    *,
    expected_key_id: str,
    epoch: int = 1,
) -> Pseudonymizer:
    """Verify and durably adopt a key after commit-uncertain creation."""

    key_path = _bound_key_path(config, paths)
    load_pseudonym_key(
        config,
        paths,
        epoch=epoch,
        expected_key_id=expected_key_id,
    )
    try:
        sync_parent_directory_no_follow(key_path, require_private_parent=True)
    except SecureFileError as error:
        if error.kind is SecureFileErrorKind.PARENT_UNSAFE:
            raise _key_error(
                "MH_PRIVACY_KEY_PARENT_UNSAFE",
                "pseudonym key parent directory must be owner-only",
            ) from None
        raise _key_error(
            "MH_PRIVACY_KEY_RECOVERY",
            "pseudonym key publication could not be durably recovered",
        ) from None
    except Exception:
        raise _key_error(
            "MH_PRIVACY_KEY_RECOVERY",
            "pseudonym key publication could not be durably recovered",
        ) from None
    return load_pseudonym_key(
        config,
        paths,
        epoch=epoch,
        expected_key_id=expected_key_id,
    )


__all__ = [
    "PSEUDONYM_KEY_MODE",
    "PseudonymKeyCommitUncertain",
    "create_pseudonym_key",
    "load_pseudonym_key",
    "recover_pseudonym_key_creation",
]
