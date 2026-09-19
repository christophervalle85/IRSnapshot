"""The offline demonstration exercises the installed APIs without endpoint access."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / 'examples' / 'interpret_snapshot.py'
SAMPLE = ROOT / 'samples' / 'benign.snapshot.json'


def run_example(cwd, *arguments):
    environment = os.environ.copy()
    environment.update(NO_COLOR='1', FORCE_COLOR='0', TERM='dumb')
    return subprocess.run([sys.executable, str(EXAMPLE), *map(str, arguments)],
                          cwd=cwd, env=environment, capture_output=True, text=True,
                          check=False, timeout=15)


def test_example_help_works_without_a_snapshot(tmp_path):
    result = run_example(tmp_path, '--help')
    assert result.returncode == 0
    assert 'snapshot' in result.stdout
    assert 'offline' in result.stdout.lower()


def test_example_interprets_sample_and_creates_no_files(tmp_path):
    before = SAMPLE.read_bytes()
    result = run_example(tmp_path, SAMPLE)
    assert result.returncode == 0, result.stderr
    assert 'EXAMPLE-LAB' in result.stdout
    assert 'explorer.exe (PID 400)' in result.stdout
    assert 'missing; reported PPID 100' in result.stdout
    assert 'pid_match' in result.stdout
    assert 'process_start' in result.stdout
    assert 'reported' in result.stdout
    assert 'collection_end' in result.stdout
    assert 'observed' in result.stdout
    assert 'No detection rules or malware verdicts' in result.stdout
    assert list(tmp_path.iterdir()) == []
    assert SAMPLE.read_bytes() == before


@pytest.mark.parametrize('contents', ['not JSON', '{"schema_version":"99"}'])
def test_example_invalid_snapshot_has_clear_error_without_traceback(tmp_path, contents):
    snapshot = tmp_path / 'invalid.json'
    snapshot.write_text(contents, encoding='utf-8')
    result = run_example(tmp_path, snapshot)
    assert result.returncode == 2
    assert 'Cannot read snapshot' in result.stderr
    assert 'Traceback' not in result.stderr


def test_example_missing_file_is_a_read_error(tmp_path):
    result = run_example(tmp_path, tmp_path / 'missing.json')
    assert result.returncode == 2
    assert 'Cannot read snapshot' in result.stderr
    assert 'Traceback' not in result.stderr


def test_example_retains_evidence_when_system_collection_failed(tmp_path, snapshot_data):
    snapshot_data['system'] = None
    run = snapshot_data['collector_runs'][0]
    run.update(status='failed', item_count=0, issues=[{
        'collector': 'system', 'observed_at': run['started_at'],
        'category': 'unavailable', 'message': 'Synthetic unavailable system',
    }])
    snapshot = tmp_path / 'partial.json'
    snapshot.write_text(json.dumps(snapshot_data), encoding='utf-8')
    result = run_example(tmp_path, snapshot)
    assert result.returncode == 0, result.stderr
    assert 'unknown host' in result.stdout
    assert 'system: failed' in result.stdout
    assert 'explorer.exe (PID 400)' in result.stdout
    assert 'collection_end' in result.stdout


def test_example_renders_captured_text_literally(tmp_path, snapshot_data):
    snapshot_data['system']['hostname'] = '[red]host\x1b[2J'
    snapshot_data['processes'][0]['name'] = '[blue]literal.exe\x1b[2J'
    snapshot = tmp_path / 'controls.json'
    snapshot.write_text(json.dumps(snapshot_data), encoding='utf-8')
    result = run_example(tmp_path, snapshot)
    assert result.returncode == 0, result.stderr
    assert '[red]host\\x1b[2J' in result.stdout
    assert '[blue]literal.exe\\x1b[2J' in result.stdout
    assert '\x1b' not in result.stdout
