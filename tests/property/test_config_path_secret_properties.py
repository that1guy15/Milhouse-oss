from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from milhouse.config import ConfigError, load_config_file
from milhouse.config.filesystem import inspect_regular_file_no_follow
from milhouse.config.loader import ConfigFileSelection, validated_config_digest
from milhouse.config.paths import resolve_runtime_paths
from milhouse.config.secrets import load_secret_environment

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BASE_CONFIG = load_config_file(REPOSITORY_ROOT / "config/examples/local-only.toml")


def _runtime(tmp_path: Path, *, spool: str = "spool"):
    config_dir = tmp_path / "config"
    config_dir.mkdir(exist_ok=True)
    config_path = config_dir / "milhouse.toml"
    config_path.write_text("config_version = 1\n", encoding="utf-8")
    path_config = BASE_CONFIG.paths.model_copy(update={"home": "state", "spool": spool})
    config = BASE_CONFIG.model_copy(update={"paths": path_config})
    selected = inspect_regular_file_no_follow(config_path)
    selection = ConfigFileSelection(
        path=selected.path,
        parent_identity=selected.parent_identity,
        snapshot=selected.snapshot,
        config_digest=validated_config_digest(config),
    )
    paths = resolve_runtime_paths(
        config,
        config_path=selection,
        platform_data_root=tmp_path / "platform",
        env={},
    )
    return config, paths


_PATH_SEGMENT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=1,
    max_size=24,
).filter(lambda value: value not in {".", ".."})


@settings(max_examples=50, deadline=None)
@given(segments=st.lists(_PATH_SEGMENT, min_size=1, max_size=5, unique=False))
def test_relative_runtime_children_always_remain_strictly_beneath_state_root(
    segments: list[str],
) -> None:
    relative = "/".join(segments)

    with tempfile.TemporaryDirectory() as directory:
        _config, paths = _runtime(Path(directory).resolve(), spool=relative)

        assert paths.spool != paths.state_root
        assert paths.spool.is_relative_to(paths.state_root)


@settings(max_examples=40, deadline=None)
@given(leaf=_PATH_SEGMENT)
def test_absolute_runtime_children_outside_state_root_always_fail_closed(
    leaf: str,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        tmp_path = Path(directory).resolve()
        outside = tmp_path / "outside" / leaf

        with pytest.raises(ConfigError) as excinfo:
            _runtime(tmp_path, spool=os.fspath(outside))

        assert excinfo.value.code == "config.path.escape"
        assert os.fspath(outside) not in str(excinfo.value)


_PRIVATE_TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\x00"),
    min_size=1,
    max_size=128,
)


@settings(max_examples=60, deadline=None)
@given(private_value=_PRIVATE_TEXT)
def test_arbitrary_process_secret_text_never_enters_safe_representations(
    private_value: str,
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        tmp_path = Path(directory).resolve()
        config, paths = _runtime(tmp_path)
        wrapped_value = f"private-begin::{private_value}::private-end"

        loaded = load_secret_environment(
            config,
            paths,
            process_env={"MILHOUSE_CLICKHOUSE_PASSWORD": wrapped_value},
        )
        rendered = repr(loaded) + repr(loaded.source("MILHOUSE_CLICKHOUSE_PASSWORD"))

        assert wrapped_value not in rendered
        assert os.fspath(tmp_path) not in rendered
