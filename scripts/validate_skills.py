#!/usr/bin/env python3
"""Validate the canonical Milhouse skill registry and discovery aliases."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "skills"
ALIASES_ROOT = ROOT / ".agents" / "skills"
REFERENCE_SHA = "8163a96e86656a89797869ac61905fe4641f81be"
EXPECTED_SKILLS = {
    "milhouse-compound",
    "milhouse-feedback",
    "milhouse-gate-review",
    "milhouse-ops",
    "milhouse-oss-maintainer",
}
CONTEXT_FILES = (
    ROOT / "AGENTS.md",
    ROOT / "CODEX.md",
    ROOT / "CLAUDE.md",
    ROOT / "docs" / "agents-and-tools.md",
)
REFERENCE_FILES = (
    ROOT / "docs" / "adr" / "0015-agent-engineering-workflow.md",
    ROOT / "docs" / "implementation-plan.md",
    ROOT / "docs" / "implementation-status.md",
    ROOT / "docs" / "provenance.md",
)


def parse_frontmatter(path: Path, errors: list[str]) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        errors.append(f"{path.relative_to(ROOT)}: missing opening frontmatter delimiter")
        return {}, text
    try:
        end = lines.index("---", 1)
    except ValueError:
        errors.append(f"{path.relative_to(ROOT)}: missing closing frontmatter delimiter")
        return {}, text

    metadata: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or ":" not in line:
            errors.append(f"{path.relative_to(ROOT)}: invalid frontmatter line {line!r}")
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key in metadata:
            errors.append(f"{path.relative_to(ROOT)}: duplicate frontmatter key {key}")
        metadata[key] = value

    if set(metadata) != {"name", "description"}:
        errors.append(
            f"{path.relative_to(ROOT)}: frontmatter keys must be exactly name and description"
        )
    return metadata, text


def validate_metadata(skill_dir: Path, skill_name: str, errors: list[str]) -> None:
    path = skill_dir / "agents" / "openai.yaml"
    if not path.is_file():
        errors.append(f"{path.relative_to(ROOT)}: missing")
        return
    text = path.read_text(encoding="utf-8")
    display = re.search(r'^  display_name: "([^"]+)"$', text, re.MULTILINE)
    short = re.search(r'^  short_description: "([^"]+)"$', text, re.MULTILINE)
    prompt = re.search(r'^  default_prompt: "([^"]+)"$', text, re.MULTILINE)
    if not display:
        errors.append(f"{path.relative_to(ROOT)}: missing quoted display_name")
    if not short or not 25 <= len(short.group(1)) <= 64:
        errors.append(f"{path.relative_to(ROOT)}: short_description must be 25-64 characters")
    if not prompt or f"${skill_name}" not in prompt.group(1):
        errors.append(f"{path.relative_to(ROOT)}: default_prompt must mention ${skill_name}")
    if skill_name == "milhouse-compound" and "allow_implicit_invocation: false" not in text:
        errors.append(f"{path.relative_to(ROOT)}: compound must require explicit invocation")


def validate_references(skill_dir: Path, text: str, errors: list[str]) -> None:
    for relative in sorted(set(re.findall(r"`((?:references|scripts|assets)/[^`]+)`", text))):
        candidate = skill_dir / relative
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            errors.append(f"{skill_dir.name}: missing referenced file {relative}")
            continue
        if not resolved.is_relative_to(skill_dir.resolve()):
            errors.append(f"{skill_dir.name}: referenced file escapes skill directory: {relative}")


def validate_skill(skill_name: str, errors: list[str]) -> None:
    skill_dir = SKILLS_ROOT / skill_name
    skill_path = skill_dir / "SKILL.md"
    if not skill_path.is_file():
        errors.append(f"{skill_path.relative_to(ROOT)}: missing")
        return

    metadata, text = parse_frontmatter(skill_path, errors)
    if metadata.get("name") != skill_name:
        errors.append(f"{skill_path.relative_to(ROOT)}: name must match folder")
    description = metadata.get("description", "")
    if len(description) < 80 or "Use " not in description:
        errors.append(f"{skill_path.relative_to(ROOT)}: description lacks useful trigger routing")
    if not any(marker in description for marker in ("Not for", "Never", "report only")):
        errors.append(f"{skill_path.relative_to(ROOT)}: description lacks adjacent-negative routing")
    if len(text.splitlines()) > 500:
        errors.append(f"{skill_path.relative_to(ROOT)}: body exceeds 500 lines")
    if re.search(r"\bTODO\b|Structuring This Skill|\[TODO", text, re.IGNORECASE):
        errors.append(f"{skill_path.relative_to(ROOT)}: unresolved scaffold placeholder")
    if re.search(r"/Users/|[A-Za-z]:\\\\Users\\\\", text):
        errors.append(f"{skill_path.relative_to(ROOT)}: machine-specific absolute path")

    validate_metadata(skill_dir, skill_name, errors)
    validate_references(skill_dir, text, errors)
    for json_path in skill_dir.rglob("*.json"):
        try:
            json.loads(json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{json_path.relative_to(ROOT)}: invalid JSON: {exc}")


def validate_aliases(errors: list[str]) -> None:
    if not ALIASES_ROOT.is_dir():
        errors.append(".agents/skills: missing directory")
        return
    actual = {entry.name for entry in ALIASES_ROOT.iterdir()}
    if actual != EXPECTED_SKILLS:
        errors.append(
            ".agents/skills: expected exact aliases "
            f"{sorted(EXPECTED_SKILLS)}, found {sorted(actual)}"
        )
    for skill_name in sorted(EXPECTED_SKILLS):
        alias = ALIASES_ROOT / skill_name
        if not alias.is_symlink():
            errors.append(f"{alias.relative_to(ROOT)}: must be a symlink")
            continue
        expected_target = f"../../skills/{skill_name}"
        if os.readlink(alias) != expected_target:
            errors.append(f"{alias.relative_to(ROOT)}: target must be {expected_target}")
        try:
            if alias.resolve(strict=True) != (SKILLS_ROOT / skill_name).resolve(strict=True):
                errors.append(f"{alias.relative_to(ROOT)}: does not resolve to canonical skill")
        except FileNotFoundError:
            errors.append(f"{alias.relative_to(ROOT)}: broken symlink")


def validate_context(errors: list[str]) -> None:
    for path in CONTEXT_FILES:
        if not path.is_file():
            errors.append(f"{path.relative_to(ROOT)}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        for skill_name in EXPECTED_SKILLS:
            if skill_name not in text:
                errors.append(f"{path.relative_to(ROOT)}: missing {skill_name}")
    for pointer in (ROOT / "CODEX.md", ROOT / "CLAUDE.md"):
        if "AGENTS.md" not in pointer.read_text(encoding="utf-8"):
            errors.append(f"{pointer.relative_to(ROOT)}: must point to canonical AGENTS.md")

    if (ROOT / ".codex" / "skills").exists():
        errors.append(".codex/skills must not duplicate repository skills")
    solutions = ROOT / "docs" / "solutions" / "README.md"
    if not solutions.is_file():
        errors.append("docs/solutions/README.md: missing sanitized knowledge contract")
    evaluations = ROOT / "docs" / "skill-evaluations.md"
    if not evaluations.is_file():
        errors.append("docs/skill-evaluations.md: missing behavioral evidence matrix")
    else:
        evaluation_text = evaluations.read_text(encoding="utf-8")
        for skill_name in EXPECTED_SKILLS:
            if skill_name not in evaluation_text:
                errors.append(f"docs/skill-evaluations.md: missing {skill_name} evidence")
        if evaluation_text.count("| Pass |") != len(EXPECTED_SKILLS):
            errors.append("docs/skill-evaluations.md: expected one passing row per skill")
    for path in REFERENCE_FILES:
        if not path.is_file():
            errors.append(f"{path.relative_to(ROOT)}: missing")
            continue
        if REFERENCE_SHA not in path.read_text(encoding="utf-8"):
            errors.append(f"{path.relative_to(ROOT)}: missing pinned workflow reference")


def main() -> int:
    errors: list[str] = []
    actual_skills = {entry.name for entry in SKILLS_ROOT.iterdir() if entry.is_dir()}
    if actual_skills != EXPECTED_SKILLS:
        errors.append(
            f"skills: expected exact registry {sorted(EXPECTED_SKILLS)}, "
            f"found {sorted(actual_skills)}"
        )
    for skill_name in sorted(EXPECTED_SKILLS):
        validate_skill(skill_name, errors)
    validate_aliases(errors)
    validate_context(errors)

    if errors:
        for error in errors:
            print(f"skill-check: {error}", file=sys.stderr)
        return 1
    print("skill-check: five canonical skills and discovery aliases are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
