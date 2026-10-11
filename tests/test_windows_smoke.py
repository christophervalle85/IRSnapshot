"""Explicit opt-in smoke test against the current Windows endpoint."""
from collections import Counter
import json
import os
import struct
import subprocess
import sys

import pytest

from irsnapshot.models import CollectionStatus, CollectorName, InvestigationReport, SystemSnapshot
from irsnapshot.pipeline import collect_snapshot
from irsnapshot.storage import load_snapshot, write_snapshot


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32" or struct.calcsize("P") != 8,
                    reason="live collection requires 64-bit Windows")
def test_live_local_accounts_import_from_trusted_system_module():
    """The bundled, versioned LocalAccounts module must actually enumerate accounts."""
    import ctypes
    from irsnapshot.collectors.contracts import WindowsQuery
    from irsnapshot.collectors.windows import WindowsAdapter

    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip('Local-account availability regression requires an elevated test endpoint')
    response = WindowsAdapter().run_query(WindowsQuery.USERS, timeout_seconds=120)
    sources = {item.source for item in response.items}
    assert 'current_token' in sources
    assert 'local_account' in sources
    assert 'local_admin_member' in sources


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32" or struct.calcsize("P") != 8,
                    reason="live collection requires 64-bit Windows")
def test_live_read_only_snapshot_round_trip(tmp_path):
    snapshot = collect_snapshot()
    validated = SystemSnapshot.model_validate(snapshot)
    assert {run.collector for run in validated.collector_runs} == set(CollectorName)
    assert len(validated.collector_runs) == 7
    assert validated.system is not None and validated.system.hostname
    assert validated.processes
    destination = tmp_path / "live.snapshot.json"
    write_snapshot(validated, destination)
    assert load_snapshot(destination).snapshot_id == validated.snapshot_id


@pytest.mark.windows_live
@pytest.mark.skipif(sys.platform != "win32" or struct.calcsize("P") != 8,
                    reason="live collection requires 64-bit Windows")
def test_live_cli_investigation_preserves_evidence_and_reports_coverage(tmp_path, capsys):
    """Catch live CLI, serialization, reporting and no-clobber integration failures.

    CI runs this file with the installed wheel interpreter in isolated mode.
    Child output stays captured; only typed status/count summaries leave the host.
    """
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'PYTHONPATH', 'PYTHONHOME'}}
    environment.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8', NO_COLOR='1', TERM='dumb')

    def invoke(*arguments):
        completed = subprocess.run(
            [sys.executable, '-X', 'utf8', '-I', '-m', 'irsnapshot', *map(str, arguments)],
            cwd=tmp_path, env=environment, stdin=subprocess.DEVNULL,
            capture_output=True, encoding='utf-8', timeout=600, check=False,
        )
        # No raw endpoint strings in assertion messages or CI diagnostics.
        assert 'Traceback' not in completed.stderr
        return completed.returncode

    source = tmp_path / 'snapshot.json'
    collect_exit = invoke('collect', '--output', source)
    assert collect_exit in {0, 3}
    snapshot = load_snapshot(source)
    assert {run.collector for run in snapshot.collector_runs} == set(CollectorName)
    assert snapshot.system is not None and snapshot.system.hostname
    assert snapshot.system.elevated is not None
    assert snapshot.processes
    expected_exit = 3 if any(run.status != CollectionStatus.OK for run in snapshot.collector_runs) else 0
    assert collect_exit == expected_exit
    original = source.read_bytes()
    assert invoke('collect', '--output', source) == 1
    assert source.read_bytes() == original

    analysis = tmp_path / 'analysis.json'
    html = tmp_path / 'report.html'
    assert invoke('analyze', source, '--output', analysis) == expected_exit
    report = InvestigationReport.model_validate_json(analysis.read_bytes())
    assert report.snapshot == snapshot and report.analysis.complete
    assert invoke('report', source, '--output', html) == expected_exit
    assert str(snapshot.snapshot_id) in html.read_text(encoding='utf-8')
    for command, output in [('analyze', analysis), ('report', html)]:
        before = output.read_bytes()
        assert invoke(command, source, '--output', output) == 1
        assert output.read_bytes() == before
        assert invoke(command, source, '--output', output, '--overwrite') == expected_exit
        assert output.read_bytes() == before
    assert source.read_bytes() == original

    investigation = tmp_path / 'investigation'
    run_exit = invoke('run', '--output', investigation)
    assert run_exit in {0, 3}
    assert {path.name for path in investigation.iterdir()} == {
        'snapshot.json', 'analysis.json', 'report.html', 'irsnapshot.log',
    }
    captured = load_snapshot(investigation / 'snapshot.json')
    integrated = InvestigationReport.model_validate_json((investigation / 'analysis.json').read_bytes())
    assert integrated.snapshot == captured and integrated.analysis.complete
    assert captured.system is not None and captured.system.elevated == snapshot.system.elevated
    assert captured.processes
    assert run_exit == (3 if any(run.status != CollectionStatus.OK for run in captured.collector_runs) else 0)
    assert str(captured.snapshot_id) in (investigation / 'report.html').read_text(encoding='utf-8')
    assert (investigation / 'irsnapshot.log').stat().st_size > 0
    prior = {path.name: path.read_bytes() for path in investigation.iterdir()}
    assert invoke('run', '--output', investigation) == 1
    assert all((investigation / name).read_bytes() == content for name, content in prior.items())

    for label, evidence in [('collect', snapshot), ('run', captured)]:
        # These names, statuses and categories are closed model enums/literals.
        summary = {
            'command': label, 'elevated': evidence.system.elevated,
            'exit': collect_exit if label == 'collect' else run_exit,
            'collectors': {run.collector.value: {
                'status': run.status.value, 'items': run.item_count,
                'issues': dict(Counter(issue.category for issue in run.issues)),
            } for run in evidence.collector_runs},
        }
        with capsys.disabled():
            print('Live coverage: ' + json.dumps(summary, sort_keys=True), flush=True)
