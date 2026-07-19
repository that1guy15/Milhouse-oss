from pathlib import Path

import pytest

from scripts import validate_skills
from scripts.validate_skills import EXPECTED_SKILLS, SkillValidator

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write(path: Path, content: str = "") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _validator(tmp_path: Path) -> SkillValidator:
    (tmp_path / "skills").mkdir()
    return SkillValidator(tmp_path)


def test_skill_validator_path_labels_and_regular_file_boundary(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    inside = _write(tmp_path / "skills" / "skill" / "file", "content")
    outside = _write(tmp_path / "outside", "content")
    linked = tmp_path / "skills" / "linked"
    linked.symlink_to(inside)

    assert validator.relative(inside) == "skills/skill/file"
    assert validator.relative(Path("/not-beneath-repository")) == "/not-beneath-repository"
    assert validator.require_regular_file(inside)
    assert not validator.require_regular_file(outside)
    assert not validator.require_regular_file(linked)
    assert not validator.require_regular_file(tmp_path / "skills" / "missing")
    assert any("resolves outside" in error for error in validator.errors)


def test_frontmatter_parser_accepts_exact_metadata_and_rejects_ambiguous_forms(
    tmp_path: Path,
) -> None:
    validator = _validator(tmp_path)
    valid = _write(
        tmp_path / "skills" / "valid.md",
        '---\nname: "example"\ndescription: "Useful description"\n---\nBody\n',
    )
    metadata, text = validator.parse_frontmatter(valid)
    assert metadata == {"name": "example", "description": "Useful description"}
    assert text.endswith("Body\n")

    missing_open = _write(tmp_path / "skills" / "missing-open.md", "body")
    assert validator.parse_frontmatter(missing_open)[0] == {}
    missing_close = _write(tmp_path / "skills" / "missing-close.md", "---\nname: x")
    assert validator.parse_frontmatter(missing_close)[0] == {}
    malformed = _write(
        tmp_path / "skills" / "malformed.md",
        "---\n"
        ' name: "indented"\n'
        'bad-key: "value"\n'
        'name: "first"\n'
        'name: "second"\n'
        "description: 3\n"
        "other: unquoted\n"
        "---\n",
    )
    metadata, _text = validator.parse_frontmatter(malformed)
    assert metadata == {"name": "first"}
    assert any("invalid flat frontmatter" in error for error in validator.errors)
    assert any("invalid frontmatter key" in error for error in validator.errors)
    assert any("duplicate frontmatter" in error for error in validator.errors)
    assert any("value must be a quoted JSON string" in error for error in validator.errors)
    assert any("frontmatter value must be a string" in error for error in validator.errors)


def test_exact_yaml_parser_covers_boolean_and_strict_failure_shapes(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    path = _write(
        tmp_path / "skills" / "metadata.yaml",
        "interface:\n"
        '  display_name: "Display"\n'
        "  enabled: true\n"
        "  disabled: false\n"
        "  count: 3\n"
        "  raw: unquoted\n"
        '  display_name: "Duplicate"\n'
        "\tbad: true\n"
        "invalid top level\n"
        "interface:\n"
        "    nested: true\n",
    )

    parsed = validator.parse_exact_yaml(path)

    assert parsed["interface"]["enabled"] is True
    assert parsed["interface"]["disabled"] is False
    assert any("scalar must be a string or boolean" in error for error in validator.errors)
    assert any("scalar must be quoted JSON" in error for error in validator.errors)
    assert any("duplicate key" in error for error in validator.errors)
    assert any("tabs are not allowed" in error for error in validator.errors)
    assert any("expected a mapping section" in error for error in validator.errors)
    assert any("duplicate section" in error for error in validator.errors)
    assert any("invalid nesting" in error for error in validator.errors)


@pytest.mark.parametrize("skill_name", ["milhouse-ops", "milhouse-compound"])
def test_metadata_validator_reports_interface_and_compound_policy_drift(
    tmp_path: Path,
    skill_name: str,
) -> None:
    validator = _validator(tmp_path)
    skill_dir = tmp_path / "skills" / skill_name
    _write(
        skill_dir / "agents" / "openai.yaml",
        "interface:\n"
        '  display_name: ""\n'
        '  short_description: "short"\n'
        '  default_prompt: "missing invocation"\n'
        "  unexpected: true\n"
        "policy:\n"
        "  allow_implicit_invocation: true\n"
        "  extra: false\n",
    )

    validator.validate_metadata(skill_dir, skill_name)

    if skill_name == "milhouse-ops":
        assert any("sections must be exactly" in error for error in validator.errors)
    assert any("interface keys must be exactly" in error for error in validator.errors)
    assert any("display_name must be" in error for error in validator.errors)
    assert any("short_description must be" in error for error in validator.errors)
    assert any("default_prompt must mention" in error for error in validator.errors)
    if skill_name == "milhouse-compound":
        assert any("policy must contain only" in error for error in validator.errors)
        assert any("must be boolean false" in error for error in validator.errors)


def test_skill_validation_rejects_missing_symlinked_and_scaffold_content(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    validator.validate_skill("milhouse-ops")
    assert any("missing canonical skill directory" in error for error in validator.errors)

    validator.errors.clear()
    target = tmp_path / "target"
    target.mkdir()
    alias_dir = tmp_path / "skills" / "milhouse-ops"
    alias_dir.symlink_to(target, target_is_directory=True)
    validator.validate_skill("milhouse-ops")
    assert any("must not be a symlink" in error for error in validator.errors)

    alias_dir.unlink()
    alias_dir.mkdir()
    _write(
        alias_dir / "SKILL.md",
        '---\nname: "wrong"\ndescription: "too short"\n---\nTODO\n',
    )
    _write(alias_dir / "invalid.json", "{")
    nested_target = _write(tmp_path / "nested-target", "content")
    (alias_dir / "nested-link").symlink_to(nested_target)
    validator.errors.clear()
    validator.validate_skill("milhouse-ops")
    assert any("symlink is prohibited" in error for error in validator.errors)
    assert any("name must match folder" in error for error in validator.errors)
    assert any("description lacks useful" in error for error in validator.errors)
    assert any("adjacent-negative" in error for error in validator.errors)
    assert any("unresolved scaffold" in error for error in validator.errors)
    assert any("missing canonical mutation boundary" in error for error in validator.errors)
    assert any("invalid JSON" in error for error in validator.errors)


def test_canonical_tree_alias_and_order_checks_fail_closed(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    validator.validate_canonical_tree()
    assert any("expected exact registry" in error for error in validator.errors)

    validator.validate_aliases()
    assert any("missing real alias directory" in error for error in validator.errors)

    aliases = tmp_path / ".agents" / "skills"
    aliases.mkdir(parents=True)
    for name in EXPECTED_SKILLS:
        (tmp_path / "skills" / name).mkdir(exist_ok=True)
    (aliases / "milhouse-ops").symlink_to("wrong")
    validator.errors.clear()
    validator.validate_aliases()
    assert any("expected exact aliases" in error for error in validator.errors)
    assert any("target must be" in error for error in validator.errors)
    assert any("broken symlink" in error for error in validator.errors)

    hierarchy = _write(tmp_path / "hierarchy.md", "second first")
    validator.require_order(hierarchy, ("first", "second"))
    validator.require_order(tmp_path / "missing-hierarchy.md", ("first",))
    assert any("missing or out of order" in error for error in validator.errors)
    assert any("missing regular hierarchy" in error for error in validator.errors)


def test_context_and_privacy_validation_report_missing_and_binary_evidence(tmp_path: Path) -> None:
    validator = _validator(tmp_path)
    validator.validate_context()
    assert any("missing regular context file" in error for error in validator.errors)
    assert any("explicit-only compound routing" in error for error in validator.errors)
    assert any("missing sanitized knowledge contract" in error for error in validator.errors)
    assert any("missing behavioral evidence matrix" in error for error in validator.errors)
    assert any("missing regular reference file" in error for error in validator.errors)
    assert any("missing regular publication checklist" in error for error in validator.errors)
    assert any("missing regular status ledger" in error for error in validator.errors)

    skill_dir = tmp_path / "skills" / "milhouse-ops"
    skill_dir.mkdir()
    binary = skill_dir / "binary.bin"
    binary.write_bytes(b"\xff")
    validator.errors.clear()
    validator.validate_privacy()
    assert any("binary content is prohibited" in error for error in validator.errors)


def test_validate_skills_main_succeeds_for_repository_and_reports_invalid_root(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert validate_skills.main(["--root", str(REPO_ROOT)]) == 0
    assert "five canonical skills" in capsys.readouterr().out

    with pytest.raises(SystemExit):
        # argparse remains fail-closed for unsupported flags.
        validate_skills.main(["--unsupported"])

    assert validate_skills.main(["--root", str(tmp_path)]) == 1
    assert "skill-check:" in capsys.readouterr().err
