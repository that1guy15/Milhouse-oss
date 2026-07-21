from pathlib import Path

from click.testing import CliRunner

from milhouse.cli import main

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_every_public_example_validates_through_the_cli() -> None:
    examples = (
        REPOSITORY_ROOT / "config/example.toml",
        REPOSITORY_ROOT / "config/examples/ai-agent-workflows.toml",
        REPOSITORY_ROOT / "config/examples/cloudflare-sites.toml",
        REPOSITORY_ROOT / "config/examples/local-only.toml",
    )

    for example in examples:
        result = CliRunner().invoke(
            main,
            ["--config", str(example), "config", "validate"],
        )
        assert result.exit_code == 0, result.output
        assert result.output == "configuration is valid\n"
