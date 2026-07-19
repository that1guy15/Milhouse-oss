from click.testing import CliRunner

from milhouse.cli import main
from milhouse.resources import load_manifest


def test_cli_and_resources_work_outside_the_repository_working_directory() -> None:
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(main, ["--help"])
        manifest = load_manifest()

    assert result.exit_code == 0
    assert manifest.import_package == "milhouse"
    assert "resources/manifest.json" in manifest.resources
