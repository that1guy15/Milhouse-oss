from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from milhouse.config import load_config, resolve_runtime_paths
from milhouse.privacy import create_pseudonym_key, load_pseudonym_key

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_CONFIG = REPOSITORY_ROOT / "config/examples/local-only.toml"


@settings(max_examples=40, deadline=None)
@given(key=st.binary(min_size=32, max_size=32), epoch=st.integers(min_value=1, max_value=10_000))
def test_every_exact_key_round_trips_without_public_material(
    key: bytes,
    epoch: int,
) -> None:
    temporary_root = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(
        prefix="milhouse-key-property-",
        dir=temporary_root,
    ) as directory:
        tmp_path = Path(directory)
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_file = config_dir / "milhouse.toml"
        config_file.write_text(
            EXAMPLE_CONFIG.read_text(encoding="utf-8").replace(
                'home = "../../data/local-only"',
                'home = "../state"',
            ),
            encoding="utf-8",
        )
        config, selection = load_config(config_file, platform_default=config_file, env={})
        paths = resolve_runtime_paths(
            config,
            config_path=selection,
            platform_data_root=tmp_path / "platform",
            env={},
        )
        paths.pseudonym_key.parent.mkdir(parents=True, mode=0o700)

        created = create_pseudonym_key(
            config,
            paths,
            epoch=epoch,
            random_bytes=lambda size: key,
        )
        loaded = load_pseudonym_key(
            config,
            paths,
            epoch=epoch,
            expected_key_id=created.key_id,
        )

        assert re.fullmatch(r"mh_pk1_[0-9a-f]{16}", created.key_id)
        assert created.key_id == loaded.key_id
        assert repr(created) == f"Pseudonymizer(epoch={epoch})"
        assert key.hex() not in repr(created)
        assert os.fspath(paths.pseudonym_key) not in repr(created)
