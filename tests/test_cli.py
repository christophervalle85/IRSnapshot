from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from irsnapshot import __version__
from irsnapshot.cli import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


def assert_milestone_help(output: str) -> None:
    assert "IRSnapshot Milestone 2" in output
    assert "--version" in output
    assert "--help" in output
    assert not re.search(
        r"(?m)^\s+(collect|analyze|report|run)\s",
        output,
    )


def test_version_matches_package_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"IRSnapshot {__version__}"


def test_help_describes_the_current_milestone_without_future_commands() -> None:
    result = runner.invoke(app, ["--help"], color=False)

    assert result.exit_code == 0
    assert_milestone_help(result.stdout)


def test_bare_invocation_prints_help_and_succeeds() -> None:
    result = runner.invoke(app, [], color=False)

    assert result.exit_code == 0
    assert_milestone_help(result.stdout)


def test_nonexistent_command_is_a_usage_error() -> None:
    result = runner.invoke(app, ["collect"], color=False)

    assert result.exit_code == 2
    assert "No such command 'collect'" in result.output


@pytest.mark.parametrize(
    ("arguments", "expected_exit_code"),
    [
        (("--help",), 0),
        (("--version",), 0),
        ((), 0),
        (("collect",), 2),
    ],
)
def test_python_module_entry_point(
    arguments: tuple[str, ...], expected_exit_code: int
) -> None:
    environment = os.environ.copy()
    environment.update({"NO_COLOR": "1", "FORCE_COLOR": "0", "TERM": "dumb"})

    result = subprocess.run(
        [sys.executable, "-m", "irsnapshot", *arguments],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == expected_exit_code
    if arguments == ("--version",):
        assert result.stdout.strip() == f"IRSnapshot {__version__}"
    elif arguments in {("--help",), ()}:
        assert_milestone_help(result.stdout)
    else:
        assert "No such command 'collect'" in result.stderr
