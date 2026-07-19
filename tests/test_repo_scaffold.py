import os
import shutil
from pathlib import Path

import pytest

from scripts.validate_skills import validate_repository

VALIDATION_FILES = (
    "AGENTS.md",
    "CODEX.md",
    "CLAUDE.md",
    "docs/agents-and-tools.md",
    "docs/adr/0015-agent-engineering-workflow.md",
    "docs/implementation-plan.md",
    "docs/implementation-status.md",
    "docs/provenance.md",
    "docs/publication-checklist.md",
    "docs/skill-evaluations.md",
    "docs/solutions/README.md",
)


def test_required_docs_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        "README.md",
        "LICENSE",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "AGENTS.md",
        "CODEX.md",
        "CLAUDE.md",
        "docs/architecture.md",
        "docs/project-plan.md",
        "docs/agents-and-tools.md",
        "docs/feedback-loop.md",
        "docs/skill-evaluations.md",
        "docs/adr/0015-agent-engineering-workflow.md",
        "docs/solutions/README.md",
        "scripts/validate_skills.py",
    ]

    for relative in required:
        assert (root / relative).is_file(), relative


def test_repository_skill_registry_validates() -> None:
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [sys.executable, "scripts/validate_skills.py"],
        cwd=root,
        check=True,
        text=True,
    )


@pytest.fixture
def validation_tree_factory(tmp_path: Path):
    source_root = Path(__file__).resolve().parents[1]
    counter = 0

    def build() -> Path:
        nonlocal counter
        counter += 1
        fixture_root = tmp_path / f"repository-{counter}"
        fixture_root.mkdir()
        shutil.copytree(source_root / "skills", fixture_root / "skills", symlinks=True)
        shutil.copytree(source_root / ".agents", fixture_root / ".agents", symlinks=True)
        for relative in VALIDATION_FILES:
            source = source_root / relative
            destination = fixture_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        assert validate_repository(fixture_root) == []
        return fixture_root

    return build


def test_skill_metadata_rejects_malformed_or_mis_scoped_yaml(validation_tree_factory) -> None:
    mutations = (
        ("interface:\n", "interface\n"),
        ("interface:\n", "interface:\ninterface:\n"),
        ('  display_name: "Milhouse Ops"\n', '  unexpected: "Milhouse Ops"\n'),
        ('  display_name: "Milhouse Ops"\n', 'display_name: "Milhouse Ops"\n'),
    )
    for old, new in mutations:
        fixture_root = validation_tree_factory()
        metadata = fixture_root / "skills" / "milhouse-ops" / "agents" / "openai.yaml"
        metadata.write_text(
            metadata.read_text(encoding="utf-8").replace(old, new, 1),
            encoding="utf-8",
        )
        assert validate_repository(fixture_root)

    fixture_root = validation_tree_factory()
    metadata = fixture_root / "skills" / "milhouse-compound" / "agents" / "openai.yaml"
    metadata.write_text(
        metadata.read_text(encoding="utf-8").replace(
            "  allow_implicit_invocation: false",
            '  note: "allow_implicit_invocation: false"',
        ),
        encoding="utf-8",
    )
    errors = validate_repository(fixture_root)
    assert any("allow_implicit_invocation" in error for error in errors)


def test_skill_frontmatter_rejects_invalid_yaml_and_non_strings(validation_tree_factory) -> None:
    source_root = Path(__file__).resolve().parents[1]
    source_text = (source_root / "skills" / "milhouse-ops" / "SKILL.md").read_text(encoding="utf-8")
    name_line = 'name: "milhouse-ops"'
    description_line = next(
        line for line in source_text.splitlines() if line.startswith("description: ")
    )
    mutations = (
        source_text.replace(description_line, description_line[:-1], 1),
        source_text.replace(description_line, 'description: ["invalid"]', 1),
        source_text.replace(name_line, 'name = "milhouse-ops"', 1),
        source_text.replace(name_line, f"{name_line}\n{name_line}", 1),
    )
    for mutation in mutations:
        fixture_root = validation_tree_factory()
        skill = fixture_root / "skills" / "milhouse-ops" / "SKILL.md"
        skill.write_text(mutation, encoding="utf-8")
        assert any("frontmatter" in error for error in validate_repository(fixture_root))


def test_canonical_skill_sources_reject_symlinks(validation_tree_factory, tmp_path: Path) -> None:
    fixture_root = validation_tree_factory()
    skill_dir = fixture_root / "skills" / "milhouse-feedback"
    outside_skill = tmp_path / "outside-skill"
    shutil.copytree(skill_dir, outside_skill)
    shutil.rmtree(skill_dir)
    os.symlink(outside_skill, skill_dir)
    assert any(
        "skill directory must not be a symlink" in error
        for error in validate_repository(fixture_root)
    )

    symlink_cases = (
        "skills/milhouse-ops/SKILL.md",
        "skills/milhouse-ops/agents/openai.yaml",
        "skills/milhouse-ops/references/checklist.md",
    )
    for index, relative in enumerate(symlink_cases):
        fixture_root = validation_tree_factory()
        canonical = fixture_root / relative
        outside_file = tmp_path / f"outside-{index}.txt"
        shutil.copy2(canonical, outside_file)
        canonical.unlink()
        os.symlink(outside_file, canonical)
        errors = validate_repository(fixture_root)
        assert any("symlink" in error for error in errors)


def test_context_parity_rejects_authority_and_explicit_routing_drift(
    validation_tree_factory,
) -> None:
    fixture_root = validation_tree_factory()
    agents = fixture_root / "AGENTS.md"
    text = agents.read_text(encoding="utf-8")
    text = text.replace("2. Accepted ADRs", "9. Accepted ADRs", 1)
    agents.write_text(text, encoding="utf-8")
    assert any("authority hierarchy" in error for error in validate_repository(fixture_root))

    fixture_root = validation_tree_factory()
    ops = fixture_root / "skills" / "milhouse-ops" / "SKILL.md"
    ops.write_text(
        ops.read_text(encoding="utf-8").replace(
            "only when explicitly requested and ",
            "only when ",
        ),
        encoding="utf-8",
    )
    assert any("explicit-only compound" in error for error in validate_repository(fixture_root))

    fixture_root = validation_tree_factory()
    agents = fixture_root / "AGENTS.md"
    agents.write_text(
        agents.read_text(encoding="utf-8").replace(
            "- `milhouse-ops`: implement, debug, simplify, test, and validate",
            "- `milhouse-ops`: observe",
        ),
        encoding="utf-8",
    )
    assert any("canonical skill role" in error for error in validate_repository(fixture_root))

    fixture_root = validation_tree_factory()
    feedback = fixture_root / "skills" / "milhouse-feedback" / "SKILL.md"
    feedback.write_text(
        feedback.read_text(encoding="utf-8").replace(
            "never authorizes source, GitHub, provider, or external-state mutation",
            "may authorize external mutation",
        ),
        encoding="utf-8",
    )
    assert any("mutation boundary" in error for error in validate_repository(fixture_root))


@pytest.mark.parametrize(
    ("relative", "mutation"),
    (
        ("skills/milhouse-ops/references/checklist.md", "\n/Users/example/private.txt\n"),
        ("skills/milhouse-ops/references/checklist.md", "\n/home/example/private.txt\n"),
        ("skills/milhouse-ops/references/checklist.md", "\nC:\\Users\\example\\private.txt\n"),
        (
            "skills/milhouse-ops/agents/openai.yaml",
            "\nRaw prompt: synthetic prohibited content\n",
        ),
        ("docs/skill-evaluations.md", "\nRaw prompt: synthetic prohibited content\n"),
        ("docs/skill-evaluations.md", "\n/root/private.txt\n"),
        ("AGENTS.md", "\nRaw session: synthetic prohibited content\n"),
    ),
)
def test_privacy_scan_covers_skill_and_context_files(
    validation_tree_factory,
    relative: str,
    mutation: str,
) -> None:
    fixture_root = validation_tree_factory()
    target = fixture_root / relative
    target.write_text(target.read_text(encoding="utf-8") + mutation, encoding="utf-8")
    assert any("prohibited" in error for error in validate_repository(fixture_root))


def test_publication_checklist_keeps_third_party_pvr_smoke_open(validation_tree_factory) -> None:
    fixture_root = validation_tree_factory()
    checklist = fixture_root / "docs" / "publication-checklist.md"
    checklist.write_text(
        checklist.read_text(encoding="utf-8").replace(
            "- [ ] Third-party reporter-to-reviewer delivery",
            "- [x] Third-party reporter-to-reviewer delivery",
        ),
        encoding="utf-8",
    )
    assert any(
        "G17 third-party PVR smoke must remain open" in error
        for error in validate_repository(fixture_root)
    )

    fixture_root = validation_tree_factory()
    checklist = fixture_root / "docs" / "publication-checklist.md"
    checklist.write_text(
        checklist.read_text(encoding="utf-8")
        + "\n- [x] Third-party reporter-to-reviewer delivery was not actually tested.\n",
        encoding="utf-8",
    )
    assert any(
        "G17 third-party PVR smoke must remain open" in error
        for error in validate_repository(fixture_root)
    )
