"""Full workflow evidence preservation, destination and scoped diagnostic contracts."""
import json
import logging
from pathlib import Path

import pytest

from irsnapshot.models import InvestigationReport
from irsnapshot.storage import load_snapshot

ROOT = Path(__file__).resolve().parents[1]


def install_collection(monkeypatch, sample='benign'):
    import irsnapshot.investigation as investigation
    snapshot = load_snapshot(ROOT / f'samples/{sample}.snapshot.json')
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: snapshot)
    return snapshot


@pytest.mark.parametrize('sample,partial', [('benign', False), ('review', False), ('partial', True)])
def test_real_analysis_and_writers_preserve_original_snapshot(tmp_path, monkeypatch, sample, partial):
    from irsnapshot.investigation import run_investigation
    snapshot = install_collection(monkeypatch, sample)
    output = tmp_path / 'investigation'
    report = run_investigation(output)
    assert report.snapshot == snapshot
    assert load_snapshot(output / 'snapshot.json') == snapshot
    assert InvestigationReport.model_validate_json((output / 'analysis.json').read_bytes()) == report
    html = (output / 'report.html').read_text(encoding='utf-8')
    assert ('Partial investigation' in html) == partial
    assert str(snapshot.snapshot_id) in html
    log = (output / 'irsnapshot.log').read_text(encoding='utf-8')
    assert 'UTC' in log and 'snapshot saved' in log.lower() and 'completed' in log.lower()
    assert {p.name for p in output.iterdir()} == {'snapshot.json', 'analysis.json', 'report.html', 'irsnapshot.log'}


@pytest.mark.parametrize('kind', ['file', 'nonempty', 'symlink', 'snapshot_dir', 'analysis_dir', 'report_dir', 'log_dir', 'snapshot_symlink', 'analysis_symlink', 'log_symlink', 'report_symlink'])
@pytest.mark.parametrize('overwrite', [False, True])
def test_invalid_destinations_never_collect(tmp_path, monkeypatch, kind, overwrite):
    from irsnapshot.investigation import run_investigation
    import irsnapshot.investigation as investigation
    target = tmp_path / 'investigation'
    if kind == 'file':
        target.write_text('evidence')
    elif kind == 'symlink':
        other = tmp_path / 'real'
        other.mkdir()
        target.symlink_to(other, target_is_directory=True)
    else:
        target.mkdir()
        if kind == 'nonempty':
            (target / 'notes.txt').write_text('notes')
        elif kind.endswith('_dir'):
            (target / {'snapshot': 'snapshot.json', 'analysis': 'analysis.json', 'report': 'report.html', 'log': 'irsnapshot.log'}[kind.split('_')[0]]).mkdir()
        else:
            other = tmp_path / 'evidence'
            other.write_text('untouched')
            (target / {'snapshot': 'snapshot.json', 'analysis': 'analysis.json', 'report': 'report.html', 'log': 'irsnapshot.log'}[kind.split('_')[0]]).symlink_to(other)
    if kind == 'nonempty' and overwrite:
        snapshot = install_collection(monkeypatch)
        result = run_investigation(target, overwrite=True)
        assert result.snapshot == snapshot
        assert (target / 'notes.txt').read_text() == 'notes'
        return
    def forbidden():
        pytest.fail('endpoint collection called for invalid destination')
    monkeypatch.setattr(investigation, 'collect_snapshot', forbidden)
    with pytest.raises((OSError, ValueError)):
        run_investigation(target, overwrite=overwrite)
    if (tmp_path / 'evidence').exists():
        assert (tmp_path / 'evidence').read_text() == 'untouched'


@pytest.mark.parametrize('stage', ['analyze_snapshot', 'write_json_report', 'write_html_report'])
@pytest.mark.parametrize('interrupt', [False, True])
def test_downstream_failure_retains_saved_snapshot_and_safe_chained_log(tmp_path, monkeypatch, stage, interrupt):
    from irsnapshot.investigation import InvestigationError, run_investigation
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    def fail(*args, **kwargs):
        if interrupt:
            raise KeyboardInterrupt()
        try:
            raise ValueError('cause\x1b[2J\rspoof')
        except ValueError as exc:
            raise RuntimeError('outer\x07\nforged') from exc
    monkeypatch.setattr(investigation, stage, fail)
    output = tmp_path / 'investigation'
    with pytest.raises(KeyboardInterrupt if interrupt else InvestigationError) as caught:
        run_investigation(output)
    assert load_snapshot(output / 'snapshot.json') == snapshot
    assert caught.value.snapshot_path == output / 'snapshot.json'
    assert not (output / 'report.html').exists()
    log = (output / 'irsnapshot.log').read_text()
    assert 'completed' not in log.lower()
    if not interrupt:
        assert 'Traceback' in log and 'ValueError' in log and 'RuntimeError' in log
        assert '\\x1b' in log and '\\r' in log and '\\x07' in log and '\\nforged' in log
        assert '\x1b' not in log and '\r' not in log and '\x07' not in log


@pytest.mark.parametrize('failure', ['collection', 'snapshot', 'analysis'])
def test_overwrite_keeps_prior_evidence_until_snapshot_saved_and_removes_stale_reports(tmp_path, monkeypatch, failure):
    from irsnapshot.investigation import InvestigationError, run_investigation
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    output = tmp_path / 'investigation'
    output.mkdir()
    for name in ['snapshot.json', 'analysis.json', 'report.html', 'notes.txt']:
        (output / name).write_text('prior evidence')
    seam = {'collection': 'collect_snapshot', 'snapshot': 'write_snapshot', 'analysis': 'analyze_snapshot'}[failure]
    def fail(*args, **kwargs):
        raise OSError('stage unavailable')
    monkeypatch.setattr(investigation, seam, fail)
    with pytest.raises(InvestigationError):
        run_investigation(output, overwrite=True)
    assert (output / 'notes.txt').read_text() == 'prior evidence'
    if failure == 'analysis':
        assert load_snapshot(output / 'snapshot.json') == snapshot
        assert not (output / 'analysis.json').exists()
        assert not (output / 'report.html').exists()
    else:
        assert (output / 'snapshot.json').read_text() == 'prior evidence'
        assert (output / 'analysis.json').read_text() == 'prior evidence'
        assert (output / 'report.html').read_text() == 'prior evidence'


def logger_state(logger):
    return (logger.level, logger.propagate, logger.disabled, list(logger.handlers))


@pytest.mark.parametrize('failure', [None, 'runtime', 'interrupt'])
def test_scoped_logger_restores_all_state_and_does_not_emit_raw_evidence(tmp_path, monkeypatch, capsys, failure):
    from irsnapshot.investigation import run_investigation
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    package = logging.getLogger('irsnapshot')
    child = logging.getLogger('irsnapshot.pipeline')
    root = logging.getLogger()
    child_handler = logging.StreamHandler()
    child.addHandler(child_handler)
    child.setLevel(logging.WARNING)
    child.propagate = False
    package.disabled = True
    saved = {logger: logger_state(logger) for logger in [package, child, root]}
    def collect():
        child.error('evidence\x1b[2J\rspoof\nnew-line')
        if failure == 'runtime':
            raise RuntimeError('private command')
        if failure == 'interrupt':
            raise KeyboardInterrupt()
        return snapshot
    monkeypatch.setattr(investigation, 'collect_snapshot', collect)
    try:
        if failure:
            with pytest.raises(KeyboardInterrupt if failure == 'interrupt' else RuntimeError):
                run_investigation(tmp_path)
        else:
            run_investigation(tmp_path)
        assert all(logger_state(logger) == state for logger, state in saved.items())
        assert capsys.readouterr().err == ''
        log = (tmp_path / 'irsnapshot.log').read_text()
        assert 'evidence\\x1b[2J\\rspoof\\nnew-line' in log
        # The handler's stream is closed: destination can be removed immediately.
        (tmp_path / 'irsnapshot.log').unlink()
    finally:
        child.removeHandler(child_handler)
        child_handler.close()
        package.disabled = False
        child.propagate = True
        child.setLevel(logging.NOTSET)


def test_log_hardlink_is_replaced_without_touching_unrelated_file(tmp_path, monkeypatch):
    from irsnapshot.investigation import run_investigation
    install_collection(monkeypatch)
    unrelated = tmp_path / 'unrelated.txt'
    unrelated.write_text('must remain')
    output = tmp_path / 'investigation'
    output.mkdir()
    (output / 'irsnapshot.log').hardlink_to(unrelated)
    run_investigation(output, overwrite=True)
    assert unrelated.read_text() == 'must remain'
    assert not unrelated.samefile(output / 'irsnapshot.log')


def test_log_open_failure_is_fatal_before_collection_and_restores_logger(tmp_path, monkeypatch):
    from irsnapshot.investigation import run_investigation
    import irsnapshot.investigation as investigation
    state = logger_state(logging.getLogger('irsnapshot'))
    def fail(*args, **kwargs):
        raise OSError('private path')
    monkeypatch.setattr(investigation, '_open_log', fail)
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: pytest.fail('collection before log open'))
    with pytest.raises(OSError):
        run_investigation(tmp_path)
    assert logger_state(logging.getLogger('irsnapshot')) == state


@pytest.mark.parametrize('after_snapshot', [False, True])
def test_log_write_failure_is_fatal_without_raw_stderr_and_retains_saved_evidence(tmp_path, monkeypatch, capsys, after_snapshot):
    from irsnapshot.investigation import InvestigationError, run_investigation
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    real_open = investigation._open_log
    class BrokenStream:
        def __init__(self, stream):
            self.stream = stream
        def write(self, text):
            if not after_snapshot or 'Snapshot saved' in text:
                raise OSError('secret\x1b[2J\nforged')
            return self.stream.write(text)
        def flush(self):
            return self.stream.flush()
        def close(self):
            return self.stream.close()
    monkeypatch.setattr(investigation, '_open_log', lambda *args: BrokenStream(real_open(*args)))
    state = logger_state(logging.getLogger('irsnapshot'))
    with pytest.raises(InvestigationError) as caught:
        run_investigation(tmp_path)
    assert logger_state(logging.getLogger('irsnapshot')) == state
    assert capsys.readouterr().err == ''
    assert (caught.value.snapshot_path is not None) == after_snapshot
    if after_snapshot:
        assert load_snapshot(tmp_path / 'snapshot.json') == snapshot
    else:
        assert not (tmp_path / 'snapshot.json').exists()
    assert not (tmp_path / 'report.html').exists()


def test_snapshot_publisher_log_failure_keeps_new_evidence_and_removes_stale_reports(tmp_path, monkeypatch, capsys):
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    for name in ['snapshot.json', 'analysis.json', 'report.html']:
        (tmp_path / name).write_text('prior evidence')
    real_open = investigation._open_log
    class BrokenStream:
        def __init__(self, stream): self.stream = stream
        def write(self, text):
            if 'Saved snapshot' in text:
                raise OSError('storage log unavailable')
            return self.stream.write(text)
        def flush(self): return self.stream.flush()
        def close(self): return self.stream.close()
    monkeypatch.setattr(investigation, '_open_log', lambda *args: BrokenStream(real_open(*args)))
    with pytest.raises(investigation.InvestigationError) as caught:
        investigation.run_investigation(tmp_path, overwrite=True)
    assert caught.value.snapshot_path == tmp_path / 'snapshot.json'
    assert load_snapshot(tmp_path / 'snapshot.json') == snapshot
    assert not (tmp_path / 'analysis.json').exists()
    assert not (tmp_path / 'report.html').exists()
    assert capsys.readouterr().err == ''


def test_collector_isolation_cannot_hide_fatal_log_failure(tmp_path, monkeypatch, capsys):
    import irsnapshot.investigation as investigation
    import irsnapshot.pipeline as pipeline
    from irsnapshot.collectors.base import CollectionContext
    class Adapter:
        def ensure_supported(self): pass
    def unavailable(context):
        raise RuntimeError('private collector evidence\x1b[2J')
    # Every failed source is isolated by the actual pipeline. Its error logging
    # must still stop the workflow before a partial result is published.
    for module in [pipeline.system, pipeline.processes, pipeline.network, pipeline.users,
                   pipeline.services, pipeline.scheduled_tasks, pipeline.persistence]:
        monkeypatch.setattr(module, 'collect', lambda *args: unavailable(args[0]))
    real_open = investigation._open_log
    class BrokenStream:
        def __init__(self, stream): self.stream = stream
        def write(self, text):
            if 'collection failed' in text:
                raise OSError('diagnostic storage failed')
            return self.stream.write(text)
        def flush(self): return self.stream.flush()
        def close(self): return self.stream.close()
    monkeypatch.setattr(investigation, '_open_log', lambda *args: BrokenStream(real_open(*args)))
    monkeypatch.setattr(investigation, 'collect_snapshot', lambda: pipeline.collect_snapshot(CollectionContext(windows=Adapter())))
    with pytest.raises(investigation.InvestigationError) as caught:
        investigation.run_investigation(tmp_path)
    assert caught.value.snapshot_path is None
    assert not (tmp_path / 'snapshot.json').exists()
    assert not (tmp_path / 'report.html').exists()
    assert capsys.readouterr().err == ''


@pytest.mark.parametrize('denied', ['analysis.json', 'report.html'])
def test_cleanup_failure_attempts_both_stale_reports_and_preserves_new_snapshot(tmp_path, monkeypatch, denied):
    import irsnapshot.investigation as investigation
    snapshot = install_collection(monkeypatch)
    for name in ['snapshot.json', 'analysis.json', 'report.html', 'notes.txt']:
        (tmp_path / name).write_text('prior evidence')
    original_unlink = Path.unlink
    failure = PermissionError('private cleanup path\x1b[2J')
    def deny_one(path, *args, **kwargs):
        if path == tmp_path / denied:
            raise failure
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', deny_one)
    monkeypatch.setattr(investigation, 'analyze_snapshot', lambda *args: pytest.fail('analysis ran after stale cleanup failure'))
    with pytest.raises(investigation.InvestigationError) as caught:
        investigation.run_investigation(tmp_path, overwrite=True)
    assert caught.value.stage == 'stale report cleanup'
    assert caught.value.snapshot_path == tmp_path / 'snapshot.json'
    assert caught.value.__cause__ is failure
    assert load_snapshot(tmp_path / 'snapshot.json') == snapshot
    assert (tmp_path / denied).read_text() == 'prior evidence'
    other = 'report.html' if denied == 'analysis.json' else 'analysis.json'
    assert not (tmp_path / other).exists()
    assert (tmp_path / 'notes.txt').read_text() == 'prior evidence'
    log = (tmp_path / 'irsnapshot.log').read_text()
    assert 'stale report cleanup' in log and 'PermissionError' in log
    assert 'completed' not in log.lower()
