from pathlib import Path


def test_required_docs_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        "README.md",
        "LICENSE",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "docs/architecture.md",
        "docs/project-plan.md",
        "docs/agents-and-tools.md",
        "docs/feedback-loop.md",
    ]

    for relative in required:
        assert (root / relative).is_file(), relative
