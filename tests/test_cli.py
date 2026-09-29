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
    assert "IRSnapshot Milestone 4" in output
    assert "--version" in output
    assert "--help" in output
    assert "analyze" in output
    assert "collect" in output
    assert not re.search(
        r"(?m)^\s+(report|run)\s",
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
    result = runner.invoke(app, ["report"], color=False)

    assert result.exit_code == 2
    assert "No such command 'report'" in result.output


@pytest.mark.parametrize(
    ("arguments", "expected_exit_code"),
    [
        (("--help",), 0),
        (("--version",), 0),
        ((), 0),
        (("report",), 2),
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
        assert "No such command 'report'" in result.stderr


def test_analyze_benign_and_json_output(tmp_path):
    import json
    output = tmp_path / 'analysis.json'
    result = runner.invoke(app, ['analyze', str(PROJECT_ROOT / 'samples/benign.snapshot.json'), '--output', str(output)])
    assert result.exit_code == 0, result.output
    assert 'No findings' in result.output
    assert json.loads(output.read_text())['analysis']['complete'] is True
    original = output.read_bytes()
    result = runner.invoke(app, ['analyze', str(PROJECT_ROOT / 'samples/benign.snapshot.json'), '--output', str(output)])
    assert result.exit_code == 1 and output.read_bytes() == original
    assert runner.invoke(app, ['analyze', str(PROJECT_ROOT / 'samples/benign.snapshot.json'), '--output', str(output), '--overwrite']).exit_code == 0


@pytest.mark.parametrize('alias_kind', ['same', 'symlink', 'hardlink'])
def test_input_alias_is_never_overwritten(tmp_path, alias_kind):
    source = tmp_path / 'input.json'
    source.write_bytes((PROJECT_ROOT / 'samples/benign.snapshot.json').read_bytes())
    before = source.read_bytes()
    output = source if alias_kind == 'same' else tmp_path / 'alias.json'
    if alias_kind == 'symlink': output.symlink_to(source)
    if alias_kind == 'hardlink': output.hardlink_to(source)
    result = runner.invoke(app, ['analyze', str(source), '--output', str(output), '--overwrite'])
    assert result.exit_code == 2
    assert 'input snapshot' in result.output
    assert source.read_bytes() == before and output.read_bytes() == before


def test_missing_invalid_partial_and_usage(tmp_path, snapshot_data):
    import json
    assert runner.invoke(app, ['analyze', str(tmp_path / 'missing.json')]).exit_code == 1
    path = tmp_path / 'invalid.json'
    path.write_text('{bad json')
    assert runner.invoke(app, ['analyze', str(path)]).exit_code == 2
    assert runner.invoke(app, ['analyze']).exit_code == 2
    assert runner.invoke(app, ['analyze', str(path), '--overwrite']).exit_code == 2
    run = next(r for r in snapshot_data['collector_runs'] if r['collector'] == 'network')
    run.update(status='partial', issues=[dict(collector='network', category='access_denied', message='Some owners unavailable', observed_at=run['finished_at'])])
    path.write_text(json.dumps(snapshot_data))
    output = tmp_path / 'partial-report.json'
    result = runner.invoke(app, ['analyze', str(path), '--output', str(output)])
    assert result.exit_code == 3, result.output
    assert output.exists() and json.loads(output.read_text())['analysis']['complete'] is True


def test_cli_incomplete_analysis_fatal_and_interrupt(monkeypatch):
    import irsnapshot.cli as cli
    from irsnapshot.models import AnalysisIssue
    from irsnapshot.analyzers.engine import analyze_snapshot, AnalysisError
    def incomplete(snapshot):
        result = analyze_snapshot(snapshot)
        result.complete = False
        result.issues = [AnalysisIssue(component='rule', rule_id='X001', message='Synthetic failure')]
        return result
    arguments = ['analyze', str(PROJECT_ROOT / 'samples/benign.snapshot.json')]
    monkeypatch.setattr(cli, 'analyze_snapshot', incomplete)
    assert runner.invoke(app, arguments).exit_code == 3
    def fatal(snapshot): raise AnalysisError('Synthetic failure')
    monkeypatch.setattr(cli, 'analyze_snapshot', fatal)
    assert runner.invoke(app, arguments).exit_code == 1
    def interrupt(snapshot): raise KeyboardInterrupt()
    monkeypatch.setattr(cli, 'analyze_snapshot', interrupt)
    assert runner.invoke(app, arguments).exit_code == 130


def test_analyze_real_subprocess(tmp_path):
    output = tmp_path / 'result.json'
    result = subprocess.run([sys.executable, '-m', 'irsnapshot', 'analyze', str(PROJECT_ROOT / 'samples/benign.snapshot.json'), '--output', str(output)], cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert output.exists() and 'No findings' in result.stdout


def test_subprocess_renders_malicious_evidence_literally(tmp_path, snapshot_data):
    import json
    snapshot_data['system']['hostname'] = '[red]host[/red]\x1b[2J\rspoof'
    source = tmp_path / 'literal.json'
    source.write_text(json.dumps(snapshot_data))
    result = subprocess.run([sys.executable, '-m', 'irsnapshot', 'analyze', str(source)], cwd=PROJECT_ROOT, capture_output=True, text=True, check=False, env={**os.environ, 'NO_COLOR': '1', 'FORCE_COLOR': '0', 'TERM': 'dumb'})
    assert result.returncode == 0, result.stderr
    assert '[red]host[/red]\\x1b[2J\\rspoof' in result.stdout
    assert '\x1b' not in result.stdout
