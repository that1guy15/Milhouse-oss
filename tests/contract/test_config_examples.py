import hashlib
import json
from pathlib import Path

import pytest

from milhouse.config import generate_json_schema_bytes
from milhouse.config.loader import ConfigError, load_config_file
from milhouse.config.schema import JSON_SCHEMA_DIALECT

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PATHS = (
    Path("config/example.toml"),
    Path("config/examples/ai-agent-workflows.toml"),
    Path("config/examples/cloudflare-sites.toml"),
    Path("config/examples/local-only.toml"),
)


def _env_references(value: object) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        for key, member in value.items():
            if key.endswith("_env") and isinstance(member, str):
                references.add(member)
            references.update(_env_references(member))
    elif isinstance(value, list):
        for member in value:
            references.update(_env_references(member))
    return references


@pytest.mark.contract
@pytest.mark.parametrize("relative_path", EXAMPLE_PATHS, ids=str)
def test_every_checked_in_example_validates(relative_path: Path) -> None:
    config = load_config_file(REPOSITORY_ROOT / relative_path)

    assert config.config_version == 1
    assert config.project.default_target in {target.id for target in config.targets}


@pytest.mark.contract
def test_canonical_example_exercises_cross_referenced_sections() -> None:
    config = load_config_file(REPOSITORY_ROOT / "config/example.toml")

    assert config.collectors[0].id == "example-canary"
    assert config.receiver.sources[1].repository == "example/example-app"
    assert config.incident_rules[0].alert_rule_ids == ["example-canary-state"]


@pytest.mark.contract
def test_specialized_examples_exercise_their_intended_collectors() -> None:
    agent = load_config_file(REPOSITORY_ROOT / "config/examples/ai-agent-workflows.toml")
    cloudflare = load_config_file(REPOSITORY_ROOT / "config/examples/cloudflare-sites.toml")
    local = load_config_file(REPOSITORY_ROOT / "config/examples/local-only.toml")

    assert {collector.type for collector in agent.collectors} == {
        "claude_session",
        "codex_session",
        "file_outbox",
    }
    assert {collector.type for collector in cloudflare.collectors} == {
        "cloudflare",
        "site_canary",
    }
    assert local.runtime.mode == "spool_only"
    assert local.storage.clickhouse.enabled is False


@pytest.mark.contract
def test_example_environment_references_are_declared() -> None:
    required: set[str] = set()
    for relative_path in EXAMPLE_PATHS:
        config = load_config_file(REPOSITORY_ROOT / relative_path)
        required.update(_env_references(config.model_dump(mode="python")))

    declared = {
        line.partition("=")[0]
        for line in (REPOSITORY_ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    }
    assert required <= declared


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "milhouse.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _canonical_example_text() -> str:
    return (REPOSITORY_ROOT / "config/example.toml").read_text(encoding="utf-8")


@pytest.mark.contract
def test_example_with_duplicate_ids_is_rejected(tmp_path: Path) -> None:
    broken = (
        _canonical_example_text()
        + """

[[targets]]
id = "example-app"
name = "Duplicate"
kind = "web_service"
environment = "production"
"""
    )

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(_write(tmp_path, broken))

    assert excinfo.value.code == "config.schema.invalid"
    assert "duplicate entry" in excinfo.value.message


@pytest.mark.contract
def test_example_with_invalid_cross_reference_is_rejected(tmp_path: Path) -> None:
    broken = _canonical_example_text().replace(
        'collector = "example-canary"', 'collector = "no-such-collector"', 1
    )

    with pytest.raises(ConfigError) as excinfo:
        load_config_file(_write(tmp_path, broken))

    assert excinfo.value.code == "config.schema.invalid"
    assert "not bound to a declared collector id" in excinfo.value.message


def test_json_schema_bytes_are_deterministic_across_calls() -> None:
    first = generate_json_schema_bytes()
    second = generate_json_schema_bytes()

    assert first == second
    assert first.endswith(b"\n")
    assert hashlib.sha256(first).hexdigest() == (
        "6c48eb696a701229e3d0338ebf58f65e29f36b558bd298a050c8c3d6c103d304"
    )


def test_json_schema_declares_draft_2020_12() -> None:
    schema = json.loads(generate_json_schema_bytes())

    assert schema["$schema"] == JSON_SCHEMA_DIALECT
    assert JSON_SCHEMA_DIALECT == "https://json-schema.org/draft/2020-12/schema"


def test_json_schema_is_sorted_and_parses_as_valid_json() -> None:
    raw = generate_json_schema_bytes()
    schema = json.loads(raw)

    reserialized = json.dumps(schema, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    assert reserialized.encode("utf-8") == raw
