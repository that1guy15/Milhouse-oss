#!/usr/bin/env python3
"""Validate Milhouse project skills, discovery aliases, and instruction parity."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

DEFAULT_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_SHA = "8163a96e86656a89797869ac61905fe4641f81be"
EXPECTED_SKILLS = {
    "milhouse-compound",
    "milhouse-feedback",
    "milhouse-gate-review",
    "milhouse-ops",
    "milhouse-oss-maintainer",
}
AGENTS_AUTHORITY_MARKERS = (
    "1. `docs/implementation-plan.md`",
    "2. Accepted ADRs",
    "3. `docs/implementation-status.md`",
    "4. This file",
    "5. Project skills",
    "6. Host pointer files",
)
TOOLS_AUTHORITY_MARKERS = (
    "1. `docs/implementation-plan.md`",
    "2. Accepted ADRs",
    "3. `docs/implementation-status.md`",
    "4. `AGENTS.md`",
    "5. Project skills",
    "6. Host pointer files",
)
SKILL_BOUNDARIES = {
    "milhouse-compound": "only the explicitly requested sanitized documentation write",
    "milhouse-feedback": "never authorizes source, GitHub, provider, or external-state mutation",
    "milhouse-gate-review": "Skill invocation authorizes review only",
    "milhouse-ops": "never grants commit, push, PR, merge, provider-call, or publication authority",
    "milhouse-oss-maintainer": "Selecting this skill grants no external mutation authority",
}
CONTEXT_ROLE_MARKERS = {
    "AGENTS.md": (
        "- `milhouse-ops`: implement, debug, simplify, test, and validate",
        "- `milhouse-feedback`: consume normalized application feedback",
        "- `milhouse-gate-review`: independently review",
        "- `milhouse-compound`: explicitly capture one verified reusable learning",
        "- `milhouse-oss-maintainer`: handle provenance, DCO, branch, PR, check, merge",
    ),
    "docs/agents-and-tools.md": (
        "- `milhouse-ops`: implement, debug, simplify, test, and validate",
        "- `milhouse-feedback`: consume normalized feedback",
        "- `milhouse-gate-review`: independently review",
        "- `milhouse-compound`: explicitly preserve one verified reusable learning",
        "- `milhouse-oss-maintainer`: provenance, DCO, branch, PR, checks, merge",
    ),
}
SENSITIVE_PATTERNS = {
    "POSIX user path": re.compile(r"/Users/[A-Za-z0-9._-]+(?:/|\b)"),
    "Linux user path": re.compile(r"/home/[A-Za-z0-9._-]+(?:/|\b)"),
    "privileged Linux home path": re.compile(r"/root(?:/|\b)"),
    "Windows user path": re.compile(r"[A-Za-z]:\\Users\\[A-Za-z0-9._-]+"),
    "credential-shaped GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    "credential-shaped API token": re.compile(r"sk-[A-Za-z0-9]{20,}"),
    "private key": re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
    "raw agent content marker": re.compile(
        r"(?im)^(?:raw[- ]?)?(?:prompt|response|transcript|session|tool output)\s*:\s*\S"
    ),
}


class SkillValidator:
    """Validate one repository tree without following canonical-source symlinks."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.skills_root = self.root / "skills"
        self.aliases_root = self.root / ".agents" / "skills"
        self.errors: list[str] = []

    def relative(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def error(self, path: Path | str, message: str) -> None:
        label = self.relative(path) if isinstance(path, Path) else path
        self.errors.append(f"{label}: {message}")

    def require_regular_file(self, path: Path) -> bool:
        if path.is_symlink():
            self.error(path, "canonical source must be a regular file, not a symlink")
            return False
        if not path.is_file():
            self.error(path, "missing regular file")
            return False
        try:
            path.resolve(strict=True).relative_to(self.skills_root.resolve(strict=True))
        except (FileNotFoundError, ValueError):
            self.error(path, "canonical source resolves outside skills/")
            return False
        return True

    def parse_frontmatter(self, path: Path) -> tuple[dict[str, str], str]:
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if not lines or lines[0] != "---":
            self.error(path, "missing opening frontmatter delimiter")
            return {}, text
        try:
            end = lines.index("---", 1)
        except ValueError:
            self.error(path, "missing closing frontmatter delimiter")
            return {}, text

        metadata: dict[str, str] = {}
        for line_number, line in enumerate(lines[1:end], 2):
            if not line.strip() or line != line.lstrip() or ":" not in line:
                self.error(path, f"line {line_number}: invalid flat frontmatter mapping")
                continue
            key, raw_value = line.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            if not re.fullmatch(r"[a-z_]+", key):
                self.error(path, f"line {line_number}: invalid frontmatter key")
                continue
            if key in metadata:
                self.error(path, f"line {line_number}: duplicate frontmatter key {key}")
                continue
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError:
                self.error(path, f"line {line_number}: value must be a quoted JSON string")
                continue
            if not isinstance(value, str):
                self.error(path, f"line {line_number}: frontmatter value must be a string")
                continue
            metadata[key] = value

        if set(metadata) != {"name", "description"}:
            self.error(path, "frontmatter keys must be exactly name and description")
        return metadata, text

    def parse_exact_yaml(self, path: Path) -> dict[str, dict[str, Any]]:
        """Parse the deliberately small OpenAI metadata schema with strict YAML syntax."""

        result: dict[str, dict[str, Any]] = {}
        current_section: str | None = None
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            if "\t" in line:
                self.error(path, f"line {line_number}: tabs are not allowed")
                continue
            indentation = len(line) - len(line.lstrip(" "))
            stripped = line.strip()

            if indentation == 0:
                if not stripped.endswith(":") or stripped.count(":") != 1:
                    self.error(path, f"line {line_number}: expected a mapping section")
                    current_section = None
                    continue
                section = stripped[:-1]
                if section in result:
                    self.error(path, f"line {line_number}: duplicate section {section}")
                result.setdefault(section, {})
                current_section = section
                continue

            if indentation != 2 or current_section is None or ":" not in stripped:
                self.error(path, f"line {line_number}: invalid nesting")
                continue
            key, raw_value = stripped.split(":", 1)
            key = key.strip()
            raw_value = raw_value.strip()
            section_values = result[current_section]
            if key in section_values:
                self.error(path, f"line {line_number}: duplicate key {current_section}.{key}")
                continue
            if raw_value == "false":
                value: Any = False
            elif raw_value == "true":
                value = True
            else:
                try:
                    value = json.loads(raw_value)
                except json.JSONDecodeError:
                    self.error(path, f"line {line_number}: scalar must be quoted JSON or boolean")
                    continue
                if not isinstance(value, str):
                    self.error(path, f"line {line_number}: scalar must be a string or boolean")
                    continue
            section_values[key] = value
        return result

    def validate_metadata(self, skill_dir: Path, skill_name: str) -> None:
        path = skill_dir / "agents" / "openai.yaml"
        if not self.require_regular_file(path):
            return
        metadata = self.parse_exact_yaml(path)
        expected_sections = (
            {"interface", "policy"} if skill_name == "milhouse-compound" else {"interface"}
        )
        if set(metadata) != expected_sections:
            self.error(path, f"sections must be exactly {sorted(expected_sections)}")

        interface = metadata.get("interface", {})
        expected_interface = {"display_name", "short_description", "default_prompt"}
        if set(interface) != expected_interface:
            self.error(path, f"interface keys must be exactly {sorted(expected_interface)}")
        display = interface.get("display_name")
        short = interface.get("short_description")
        prompt = interface.get("default_prompt")
        if not isinstance(display, str) or not display:
            self.error(path, "display_name must be a nonempty string")
        if not isinstance(short, str) or not 25 <= len(short) <= 64:
            self.error(path, "short_description must be a 25-64 character string")
        if not isinstance(prompt, str) or f"${skill_name}" not in prompt:
            self.error(path, f"default_prompt must mention ${skill_name}")

        if skill_name == "milhouse-compound":
            policy = metadata.get("policy", {})
            if set(policy) != {"allow_implicit_invocation"}:
                self.error(path, "policy must contain only allow_implicit_invocation")
            if policy.get("allow_implicit_invocation") is not False:
                self.error(path, "policy.allow_implicit_invocation must be boolean false")

    def validate_references(self, skill_dir: Path, text: str) -> None:
        references = set(re.findall(r"`((?:references|scripts|assets)/[^`]+)`", text))
        for relative in sorted(references):
            candidate = skill_dir / relative
            if not self.require_regular_file(candidate):
                continue
            try:
                candidate.resolve(strict=True).relative_to(skill_dir.resolve(strict=True))
            except (FileNotFoundError, ValueError):
                self.error(skill_dir, f"referenced file escapes skill directory: {relative}")

    def validate_skill(self, skill_name: str) -> None:
        skill_dir = self.skills_root / skill_name
        if skill_dir.is_symlink():
            self.error(skill_dir, "canonical skill directory must not be a symlink")
            return
        if not skill_dir.is_dir():
            self.error(skill_dir, "missing canonical skill directory")
            return
        for candidate in skill_dir.rglob("*"):
            if candidate.is_symlink():
                self.error(candidate, "symlink is prohibited beneath canonical skill directory")

        skill_path = skill_dir / "SKILL.md"
        if not self.require_regular_file(skill_path):
            return
        metadata, text = self.parse_frontmatter(skill_path)
        if metadata.get("name") != skill_name:
            self.error(skill_path, "name must match folder")
        description = metadata.get("description", "")
        if len(description) < 80 or "Use " not in description:
            self.error(skill_path, "description lacks useful trigger routing")
        if not any(marker in description for marker in ("Not for", "Never", "report only")):
            self.error(skill_path, "description lacks adjacent-negative routing")
        if len(text.splitlines()) > 500:
            self.error(skill_path, "body exceeds 500 lines")
        if re.search(r"\bTODO\b|Structuring This Skill|\[TODO", text, re.IGNORECASE):
            self.error(skill_path, "unresolved scaffold placeholder")
        boundary = SKILL_BOUNDARIES[skill_name]
        if boundary not in text.replace("\n", " "):
            self.error(skill_path, "missing canonical mutation boundary")

        self.validate_metadata(skill_dir, skill_name)
        self.validate_references(skill_dir, text)
        for json_path in skill_dir.rglob("*.json"):
            if not self.require_regular_file(json_path):
                continue
            try:
                json.loads(json_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                self.error(json_path, f"invalid JSON: {exc}")

    def validate_canonical_tree(self) -> None:
        if self.skills_root.is_symlink() or not self.skills_root.is_dir():
            self.error(self.skills_root, "must be a real directory")
            return
        actual_entries = {entry.name for entry in self.skills_root.iterdir()}
        if actual_entries != EXPECTED_SKILLS:
            self.error(
                "skills",
                f"expected exact registry {sorted(EXPECTED_SKILLS)}, "
                f"found {sorted(actual_entries)}",
            )
        for skill_name in sorted(EXPECTED_SKILLS):
            self.validate_skill(skill_name)

    def validate_aliases(self) -> None:
        if self.aliases_root.is_symlink() or not self.aliases_root.is_dir():
            self.error(self.aliases_root, "missing real alias directory")
            return
        actual = {entry.name for entry in self.aliases_root.iterdir()}
        if actual != EXPECTED_SKILLS:
            self.error(
                ".agents/skills",
                f"expected exact aliases {sorted(EXPECTED_SKILLS)}, found {sorted(actual)}",
            )
        for skill_name in sorted(EXPECTED_SKILLS):
            alias = self.aliases_root / skill_name
            if not alias.is_symlink():
                self.error(alias, "must be a symlink")
                continue
            expected_target = f"../../skills/{skill_name}"
            if os.readlink(alias) != expected_target:
                self.error(alias, f"target must be {expected_target}")
            try:
                expected = (self.skills_root / skill_name).resolve(strict=True)
                if alias.resolve(strict=True) != expected:
                    self.error(alias, "does not resolve to canonical skill")
            except FileNotFoundError:
                self.error(alias, "broken symlink")

    def require_order(self, path: Path, markers: tuple[str, ...]) -> None:
        if path.is_symlink() or not path.is_file():
            self.error(path, "missing regular hierarchy file")
            return
        text = path.read_text(encoding="utf-8")
        positions = [text.find(marker) for marker in markers]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            self.error(path, "canonical authority hierarchy is missing or out of order")

    def validate_context(self) -> None:
        context_files = (
            self.root / "AGENTS.md",
            self.root / "CODEX.md",
            self.root / "CLAUDE.md",
            self.root / "docs" / "agents-and-tools.md",
        )
        for path in context_files:
            if path.is_symlink() or not path.is_file():
                self.error(path, "missing regular context file")
                continue
            text = path.read_text(encoding="utf-8")
            for skill_name in EXPECTED_SKILLS:
                if skill_name not in text:
                    self.error(path, f"missing {skill_name}")

        self.require_order(self.root / "AGENTS.md", AGENTS_AUTHORITY_MARKERS)
        self.require_order(
            self.root / "docs" / "agents-and-tools.md",
            TOOLS_AUTHORITY_MARKERS,
        )
        for relative, markers in CONTEXT_ROLE_MARKERS.items():
            role_path = self.root / relative
            if role_path.is_symlink() or not role_path.is_file():
                self.error(role_path, "missing regular role context")
                continue
            role_text = role_path.read_text(encoding="utf-8")
            for marker in markers:
                if marker not in role_text:
                    self.error(role_path, "canonical skill role is missing or changed")
        for pointer in (self.root / "CODEX.md", self.root / "CLAUDE.md"):
            if pointer.is_symlink() or not pointer.is_file():
                self.error(pointer, "missing regular host pointer")
            elif "AGENTS.md" not in pointer.read_text(encoding="utf-8"):
                self.error(pointer, "must point to canonical AGENTS.md")

        ops_dir = self.skills_root / "milhouse-ops"
        ops_path = ops_dir / "SKILL.md"
        ops_text = ""
        if (
            not self.skills_root.is_symlink()
            and not ops_dir.is_symlink()
            and not ops_path.is_symlink()
            and ops_path.is_file()
        ):
            ops_text = ops_path.read_text(encoding="utf-8")
        if "Invoke `milhouse-compound` only when explicitly requested" not in ops_text:
            self.error(
                ops_path,
                "must preserve explicit-only compound routing",
            )
        if (self.root / ".codex" / "skills").exists():
            self.error(".codex/skills", "must not duplicate repository skills")

        solutions = self.root / "docs" / "solutions" / "README.md"
        if solutions.is_symlink() or not solutions.is_file():
            self.error(solutions, "missing sanitized knowledge contract")
        evaluations = self.root / "docs" / "skill-evaluations.md"
        if evaluations.is_symlink() or not evaluations.is_file():
            self.error(evaluations, "missing behavioral evidence matrix")
        else:
            evaluation_text = evaluations.read_text(encoding="utf-8")
            for skill_name in EXPECTED_SKILLS:
                if skill_name not in evaluation_text:
                    self.error(evaluations, f"missing {skill_name} evidence")
            if evaluation_text.count("| Pass |") != len(EXPECTED_SKILLS):
                self.error(evaluations, "expected one passing row per skill")

        reference_files = (
            self.root / "docs" / "adr" / "0015-agent-engineering-workflow.md",
            self.root / "docs" / "implementation-plan.md",
            self.root / "docs" / "implementation-status.md",
            self.root / "docs" / "provenance.md",
        )
        for path in reference_files:
            if path.is_symlink() or not path.is_file():
                self.error(path, "missing regular reference file")
            elif REFERENCE_SHA not in path.read_text(encoding="utf-8"):
                self.error(path, "missing pinned workflow reference")

        publication = self.root / "docs" / "publication-checklist.md"
        status = self.root / "docs" / "implementation-status.md"
        publication_text = ""
        status_text = ""
        if publication.is_symlink() or not publication.is_file():
            self.error(publication, "missing regular publication checklist")
        else:
            publication_text = publication.read_text(encoding="utf-8")
        if status.is_symlink() or not status.is_file():
            self.error(status, "missing regular status ledger")
        else:
            status_text = status.read_text(encoding="utf-8")
        admin_checked = publication_text.count("- [x] Private vulnerability reporting is enabled")
        third_party_open = publication_text.count("- [ ] Third-party reporter-to-reviewer delivery")
        third_party_checked = publication_text.count(
            "- [x] Third-party reporter-to-reviewer delivery"
        )
        if admin_checked != 1:
            self.error(publication, "administrator PVR smoke must be complete")
        if third_party_open != 1 or third_party_checked != 0:
            self.error(publication, "G17 third-party PVR smoke must remain open")
        if "A true third-party delivery smoke is deferred to E05/G17" not in status_text:
            self.error(status, "missing deferred third-party PVR evidence")

    def validate_privacy(self) -> None:
        explicit_files = {
            self.root / "AGENTS.md",
            self.root / "CODEX.md",
            self.root / "CLAUDE.md",
            self.root / "docs" / "agents-and-tools.md",
            self.root / "docs" / "adr" / "0015-agent-engineering-workflow.md",
            self.root / "docs" / "implementation-plan.md",
            self.root / "docs" / "implementation-status.md",
            self.root / "docs" / "provenance.md",
            self.root / "docs" / "publication-checklist.md",
            self.root / "docs" / "skill-evaluations.md",
        }
        candidates = explicit_files
        if not self.skills_root.is_symlink():
            for skill_name in EXPECTED_SKILLS:
                skill_dir = self.skills_root / skill_name
                if skill_dir.is_symlink() or not skill_dir.is_dir():
                    continue
                candidates.update(path for path in skill_dir.rglob("*") if path.is_file())
        solutions_root = self.root / "docs" / "solutions"
        if solutions_root.is_symlink():
            self.error(solutions_root, "sanitized solution directory must not be a symlink")
        elif solutions_root.is_dir():
            for path in solutions_root.rglob("*"):
                if path.is_symlink():
                    self.error(path, "symlink is prohibited beneath sanitized solution directory")
                elif path.is_file():
                    candidates.add(path)

        for path in sorted(candidates):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                self.error(path, "binary content is prohibited in skill/evidence context")
                continue
            for label, pattern in SENSITIVE_PATTERNS.items():
                if pattern.search(text):
                    self.error(path, f"contains prohibited {label}")

    def run(self) -> list[str]:
        self.validate_canonical_tree()
        self.validate_aliases()
        self.validate_context()
        self.validate_privacy()
        return self.errors


def validate_repository(root: Path) -> list[str]:
    """Return deterministic validation errors for a repository root."""

    return SkillValidator(root).run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    arguments = parser.parse_args(argv)
    errors = validate_repository(arguments.root)
    if errors:
        for error in errors:
            print(f"skill-check: {error}", file=sys.stderr)
        return 1
    print("skill-check: five canonical skills and discovery aliases are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
