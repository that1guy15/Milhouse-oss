"""Canonical, class-specific configuration path resolution.

This module resolves paths without retaining an ambient working-directory dependency.  It validates
the current filesystem shape, while callers that later create or replace files must still use
race-resistant, no-follow write primitives at the mutation boundary.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from milhouse.config.errors import ConfigError
from milhouse.config.loader import (
    ConfigFileSelection,
    verify_config_generation,
)
from milhouse.config.models import MilhouseConfig

MILHOUSE_HOME_ENV_VAR = "MILHOUSE_HOME"


@dataclass(frozen=True, slots=True, repr=False)
class _RuntimePathGeneration:
    """Private snapshot proving that one set of paths came from a single resolution."""

    config_file: Path
    config_dir: Path
    config_selection: ConfigFileSelection
    state_root: Path
    spool: Path
    reports: Path
    logs: Path
    backups: Path
    pseudonym_key: Path
    configured_env_files: tuple[Path, ...]

    def __repr__(self) -> str:
        return "RuntimePathGeneration(bound=True)"

    __str__ = __repr__


@dataclass(frozen=True, slots=True, repr=False)
class RuntimePaths:
    """Immutable canonical paths whose representation never exposes local path text."""

    config_file: Path
    config_dir: Path
    config_selection: ConfigFileSelection
    state_root: Path
    spool: Path
    reports: Path
    logs: Path
    backups: Path
    pseudonym_key: Path
    configured_env_files: tuple[Path, ...]
    _generation: _RuntimePathGeneration

    def __repr__(self) -> str:
        return f"RuntimePaths(resolved=True, configured_env_files={len(self.configured_env_files)})"

    __str__ = __repr__


def verify_runtime_path_generation(paths: RuntimePaths) -> RuntimePaths:
    """Refuse runtime-path fields changed after their authoritative resolution."""

    if not isinstance(paths, RuntimePaths) or not isinstance(
        paths._generation, _RuntimePathGeneration
    ):
        raise _path_error(
            "config.paths.generation_mismatch",
            "runtime paths do not match their resolved generation",
        )
    current = _RuntimePathGeneration(
        config_file=paths.config_file,
        config_dir=paths.config_dir,
        config_selection=paths.config_selection,
        state_root=paths.state_root,
        spool=paths.spool,
        reports=paths.reports,
        logs=paths.logs,
        backups=paths.backups,
        pseudonym_key=paths.pseudonym_key,
        configured_env_files=paths.configured_env_files,
    )
    if current != paths._generation:
        raise _path_error(
            "config.paths.generation_mismatch",
            "runtime paths do not match their resolved generation",
        )
    return paths


def _path_error(code: str, message: str) -> ConfigError:
    return ConfigError(code, message)


def _normalize_absolute(path: Path) -> Path:
    try:
        normalized = Path(os.path.normpath(os.fspath(path)))
    except (TypeError, ValueError):
        raise _path_error("config.path.invalid", "configured path is invalid") from None
    if not normalized.is_absolute():
        raise _path_error(
            "config.path.not_absolute", "configured path must be absolute in this context"
        )
    return normalized


def _require_symlink_free_source_path(path: Path) -> Path:
    """Return one lexical absolute source path after inspecting every existing component.

    The lexical spelling is retained deliberately.  Canonicalizing the complete path after the
    inspection would let a leaf or parent swapped to a symlink during the check be followed before
    the descriptor-relative, no-follow open at the eventual read boundary.
    """

    normalized = _normalize_absolute(path)
    current = Path(normalized.anchor)
    components = normalized.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except NotADirectoryError:
            raise _path_error(
                "config.path.not_directory", "configured path has a non-directory parent"
            ) from None
        except (OSError, ValueError):
            raise _path_error(
                "config.path.unreadable", "configured path could not be inspected"
            ) from None
        if stat.S_ISLNK(metadata.st_mode):
            raise _path_error("config.path.symlink", "configured path must not contain symlinks")
        if index < len(components) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise _path_error(
                "config.path.not_directory", "configured path has a non-directory parent"
            )
    return normalized


def _require_directory_if_present(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        raise _path_error(
            "config.path.unreadable", "configured path could not be inspected"
        ) from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise _path_error("config.path.not_directory", "runtime path must be a directory")


def _require_regular_file_if_present(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except (OSError, ValueError):
        raise _path_error(
            "config.path.unreadable", "configured path could not be inspected"
        ) from None
    if not stat.S_ISREG(metadata.st_mode):
        raise _path_error("config.path.not_file", "runtime file path must be a regular file")


def _strict_descendant(candidate: Path, root: Path) -> Path:
    normalized = _normalize_absolute(candidate)
    try:
        relative = normalized.relative_to(root)
    except ValueError:
        raise _path_error(
            "config.path.escape", "runtime path must remain beneath STATE_ROOT"
        ) from None
    if not relative.parts:
        raise _path_error("config.path.escape", "runtime path must remain beneath STATE_ROOT")

    current = root
    for index, component in enumerate(relative.parts):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        except NotADirectoryError:
            raise _path_error(
                "config.path.not_directory", "configured path has a non-directory parent"
            ) from None
        except (OSError, ValueError):
            raise _path_error(
                "config.path.unreadable", "configured path could not be inspected"
            ) from None
        if stat.S_ISLNK(metadata.st_mode):
            raise _path_error("config.path.symlink", "runtime path must not contain symlinks")
        if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
            raise _path_error(
                "config.path.not_directory", "configured path has a non-directory parent"
            )
    return normalized


def _resolve_runtime_child(value: str, *, state_root: Path) -> Path:
    raw = Path(value)
    candidate = raw if raw.is_absolute() else state_root / raw
    return _strict_descendant(candidate, state_root)


def resolve_config_source_path(value: str | Path, *, config_dir: Path) -> Path:
    """Resolve an explicitly configured file source from the canonical config directory.

    Parent-relative paths are intentionally supported by the v1 examples.  They are lexically
    normalized and must be symlink-free, but the plan does not impose config-directory containment.
    """

    lexical_config_dir = _require_symlink_free_source_path(config_dir)
    raw = Path(value)
    candidate = raw if raw.is_absolute() else lexical_config_dir / raw
    return _require_symlink_free_source_path(candidate)


def resolve_runtime_paths(
    config: MilhouseConfig,
    *,
    config_path: ConfigFileSelection,
    platform_data_root: str | Path,
    env: Mapping[str, str] | None = None,
) -> RuntimePaths:
    """Resolve canonical runtime paths using the configuration v1 precedence contract."""

    if not isinstance(config_path, ConfigFileSelection):
        raise _path_error(
            "config.selection.required",
            "runtime paths require a securely loaded config generation",
        )
    config_selection = verify_config_generation(config, config_path)
    config_file = config_selection.path
    config_dir = config_file.parent

    environment = os.environ if env is None else env
    home_override = environment.get(MILHOUSE_HOME_ENV_VAR)
    if home_override:
        raw_state_root = Path(home_override)
        if not raw_state_root.is_absolute():
            raise _path_error("config.path.not_absolute", "MILHOUSE_HOME must be an absolute path")
    elif config.paths.home:
        configured_home = Path(config.paths.home)
        raw_state_root = (
            configured_home if configured_home.is_absolute() else config_dir / configured_home
        )
    else:
        raw_state_root = Path(platform_data_root)
        if not raw_state_root.is_absolute():
            raise _path_error("config.path.not_absolute", "platform data path must be absolute")

    state_root = _require_symlink_free_source_path(raw_state_root)
    if state_root == Path(state_root.anchor):
        raise _path_error("config.path.unsafe_root", "STATE_ROOT must not be a filesystem root")
    _require_directory_if_present(state_root)

    spool = _resolve_runtime_child(config.paths.spool, state_root=state_root)
    reports = _resolve_runtime_child(config.paths.reports, state_root=state_root)
    logs = _resolve_runtime_child(config.paths.logs, state_root=state_root)
    backups = _resolve_runtime_child(config.paths.backups, state_root=state_root)
    pseudonym_key = _resolve_runtime_child(
        config.identity.pseudonym_key_path, state_root=state_root
    )

    for directory in (spool, reports, logs, backups):
        _require_directory_if_present(directory)
    _require_regular_file_if_present(pseudonym_key)

    configured_env_files = tuple(
        resolve_config_source_path(path, config_dir=config_dir) for path in config.secrets.env_files
    )
    verify_config_generation(config, config_selection)

    generation = _RuntimePathGeneration(
        config_file=config_file,
        config_dir=config_dir,
        config_selection=config_selection,
        state_root=state_root,
        spool=spool,
        reports=reports,
        logs=logs,
        backups=backups,
        pseudonym_key=pseudonym_key,
        configured_env_files=configured_env_files,
    )
    return RuntimePaths(
        config_file=config_file,
        config_dir=config_dir,
        config_selection=config_selection,
        state_root=state_root,
        spool=spool,
        reports=reports,
        logs=logs,
        backups=backups,
        pseudonym_key=pseudonym_key,
        configured_env_files=configured_env_files,
        _generation=generation,
    )


__all__ = [
    "MILHOUSE_HOME_ENV_VAR",
    "RuntimePaths",
    "resolve_config_source_path",
    "resolve_runtime_paths",
    "verify_runtime_path_generation",
]
