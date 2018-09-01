from click.testing import CliRunner

from nucypher_cli.main import cli


def test_init():
    runner = CliRunner()
    result = runner.invoke(cli, ['simulate', 'init'], catch_exceptions=False)

    assert result.exit_code == 0
    # assert 'Debug mode is on' in result.output


def test_deploy():
    runner = CliRunner()
    result = runner.invoke(cli, ['simulate', 'deploy'], catch_exceptions=False)

    assert result.exit_code == 0

