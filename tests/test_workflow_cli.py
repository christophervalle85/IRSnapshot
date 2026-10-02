"""Offline report and full workflow command contracts at collection boundaries."""
from pathlib import Path
import pytest
from typer.testing import CliRunner
from irsnapshot.cli import app
from irsnapshot.storage import load_snapshot

ROOT = Path(__file__).resolve().parents[1]
runner = CliRunner()


@pytest.mark.parametrize('command', ['collect', 'analyze', 'report', 'run'])
def test_each_command_has_help(command):
    result = runner.invoke(app, [command, '--help'])
    assert result.exit_code == 0, result.output
    assert '--overwrite' in result.output


@pytest.mark.parametrize('sample,code', [('benign', 0), ('review', 0), ('partial', 3)])
def test_report_analyzes_offline_and_protects_existing_output(tmp_path, monkeypatch, sample, code):
    import irsnapshot.cli as cli
    monkeypatch.setattr(cli, 'collect_snapshot', lambda: pytest.fail('offline report collected endpoint'))
    output = tmp_path / '[red]report\x1b[2J.html'
    args = ['report', str(ROOT / f'samples/{sample}.snapshot.json'), '--output', str(output)]
    result = runner.invoke(app, args)
    assert result.exit_code == code, result.output
    assert 'Coverage:' in result.output and 'Outcome:' in result.output
    assert '[red]report\\x1b[2J.html' in result.output and '\x1b' not in result.output
    before = output.read_bytes()
    assert 'IRSnapshot analyst report' in before.decode()
    assert runner.invoke(app, args).exit_code == 1
    assert output.read_bytes() == before
    assert runner.invoke(app, [*args, '--overwrite']).exit_code == code


@pytest.mark.parametrize('alias', ['same', 'symlink', 'hardlink'])
def test_report_never_overwrites_input_aliases(tmp_path, alias):
    source = tmp_path / 'input.json'
    source.write_bytes((ROOT / 'samples/benign.snapshot.json').read_bytes())
    before = source.read_bytes()
    output = source if alias == 'same' else tmp_path / 'alias.html'
    if alias == 'symlink':
        output.symlink_to(source)
    elif alias == 'hardlink':
        output.hardlink_to(source)
    result = runner.invoke(app, ['report', str(source), '--output', str(output), '--overwrite'])
    assert result.exit_code == 2, result.output
    assert 'input snapshot' in result.output
    assert output.read_bytes() == source.read_bytes() == before


def test_report_guard_rechecks_identity_at_publication(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    from irsnapshot.analyzers.engine import analyze_snapshot
    source = tmp_path / 'source.json'
    source.write_bytes((ROOT / 'samples/benign.snapshot.json').read_bytes())
    before = source.read_bytes()
    output = tmp_path / 'report.html'
    def analyze(snapshot):
        output.hardlink_to(source)
        return analyze_snapshot(snapshot)
    monkeypatch.setattr(cli, 'analyze_snapshot', analyze)
    result = runner.invoke(app, ['report', str(source), '--output', str(output), '--overwrite'])
    assert result.exit_code == 2
    assert output.samefile(source)
    assert source.read_bytes() == before


def test_report_bad_input_and_interruption(tmp_path, monkeypatch):
    import irsnapshot.cli as cli
    source = tmp_path / 'invalid.json'
    source.write_text('{invalid')
    output = tmp_path / 'report.html'
    assert runner.invoke(app, ['report', str(source), '--output', str(output)]).exit_code == 2
    assert not output.exists()
    assert runner.invoke(app, ['report', str(ROOT / 'samples/benign.snapshot.json')]).exit_code == 2
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(cli, 'write_html_report', interrupt)
    assert runner.invoke(app, ['report', str(ROOT / 'samples/benign.snapshot.json'), '--output', str(output)]).exit_code == 130
    assert not output.exists()


@pytest.mark.parametrize('sample,code', [('benign', 0), ('review', 0), ('partial', 3)])
def test_run_uses_real_analysis_and_writers(tmp_path, monkeypatch, sample, code):
    import irsnapshot.investigation as investigation
    snapshot = load_snapshot(ROOT / f'samples/{sample}.snapshot.json')
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: snapshot)
    output = tmp_path / '[red]investigation'
    result = runner.invoke(app, ['run', '--output', str(output)])
    assert result.exit_code == code, result.output
    assert 'Coverage:' in result.output and 'Outcome:' in result.output
    assert '[red]investigation' in result.output
    assert load_snapshot(output / 'snapshot.json') == snapshot
    assert (output / 'analysis.json').exists() and (output / 'report.html').exists()


@pytest.mark.parametrize('interrupt', [False, True])
def test_run_failure_reports_preserved_snapshot_safely(tmp_path, monkeypatch, interrupt):
    import irsnapshot.investigation as investigation
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: load_snapshot(ROOT / 'samples/benign.snapshot.json'))
    def fail(*args, **kwargs):
        if interrupt:
            raise KeyboardInterrupt()
        raise RuntimeError('raw secret\x1b[2J')
    monkeypatch.setattr(investigation, 'write_html_report', fail)
    output = tmp_path / 'capture\x07'
    result = runner.invoke(app, ['run', '--output', str(output)])
    assert result.exit_code == (130 if interrupt else 1), result.output
    assert 'Snapshot preserved:' in result.output and 'capture\\x07' in result.output
    assert 'raw secret' not in result.output and '\x07' not in result.output
    assert (output / 'snapshot.json').exists()
    assert 'completed' not in result.output.lower()


def test_run_unsupported_platform_is_actionable_preserves_prior_evidence(tmp_path, monkeypatch):
    import irsnapshot.investigation as investigation
    from irsnapshot.collectors.windows import UnsupportedPlatformError
    def unsupported():
        raise UnsupportedPlatformError('raw secret')
    monkeypatch.setattr(investigation, 'collect_snapshot', unsupported)
    for name in ['snapshot.json', 'analysis.json', 'report.html']:
        (tmp_path / name).write_text('previous evidence')
    result = runner.invoke(app, ['run', '--output', str(tmp_path), '--overwrite'])
    assert result.exit_code == 1, result.output
    assert 'Windows' in result.output and '64-bit Python' in result.output
    assert 'report' in result.output and 'raw secret' not in result.output
    assert all((tmp_path / name).read_text() == 'previous evidence' for name in ['snapshot.json', 'analysis.json', 'report.html'])


def test_run_requires_output_and_never_collects_for_nonempty_destination(tmp_path, monkeypatch):
    import irsnapshot.investigation as investigation
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: pytest.fail('invalid destination collected'))
    assert runner.invoke(app, ['run']).exit_code == 2
    (tmp_path / 'notes.txt').write_text('keep')
    result = runner.invoke(app, ['run', '--output', str(tmp_path)])
    assert result.exit_code == 1
    assert (tmp_path / 'notes.txt').read_text() == 'keep'


def test_run_incomplete_analysis_publishes_partial_report(tmp_path, monkeypatch):
    import irsnapshot.investigation as investigation
    from irsnapshot.analyzers.engine import analyze_snapshot
    from irsnapshot.models import AnalysisIssue
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: load_snapshot(ROOT / 'samples/benign.snapshot.json'))
    def incomplete(snapshot):
        analysis = analyze_snapshot(snapshot)
        analysis.complete = False
        analysis.issues = [AnalysisIssue(component='rule', message='Synthetic rule unavailable')]
        return analysis
    monkeypatch.setattr(investigation, 'analyze_snapshot', incomplete)
    result = runner.invoke(app, ['run', '--output', str(tmp_path)])
    assert result.exit_code == 3, result.output
    assert 'partial investigation' in result.output and 'analysis incomplete' in result.output
    assert 'Incomplete' in (tmp_path / 'report.html').read_text()
    assert (tmp_path / 'snapshot.json').exists()


@pytest.mark.parametrize('denied', ['analysis.json', 'report.html'])
def test_run_cleanup_failure_reports_preserved_snapshot_without_raw_exception(tmp_path, monkeypatch, denied):
    import irsnapshot.investigation as investigation
    snapshot = load_snapshot(ROOT / 'samples/benign.snapshot.json')
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: snapshot)
    output = tmp_path / 'capture\x07'
    output.mkdir()
    for name in ['snapshot.json', 'analysis.json', 'report.html', 'notes.txt']:
        (output / name).write_text('prior evidence')
    original_unlink = Path.unlink
    def deny_one(path, *args, **kwargs):
        if path == output / denied:
            raise PermissionError('private cleanup error\x1b[2J')
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', deny_one)
    monkeypatch.setattr(investigation, 'analyze_snapshot', lambda *args: pytest.fail('analysis ran after cleanup failure'))
    result = runner.invoke(app, ['run', '--output', str(output), '--overwrite'])
    assert result.exit_code == 1, result.output
    assert 'failed during stale report cleanup' in result.output
    assert 'Snapshot preserved:' in result.output and 'capture\\x07' in result.output
    assert 'private cleanup error' not in result.output
    assert '\x07' not in result.output and '\x1b' not in result.output
    assert 'completed' not in result.output.lower()
    assert load_snapshot(output / 'snapshot.json') == snapshot
    assert (output / denied).read_text() == 'prior evidence'
    other = 'report.html' if denied == 'analysis.json' else 'analysis.json'
    assert not (output / other).exists()
    assert (output / 'notes.txt').read_text() == 'prior evidence'
