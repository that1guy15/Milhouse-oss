from pathlib import Path


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
