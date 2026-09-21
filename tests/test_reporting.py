"""Actual files and literal terminal rendering at report boundaries."""
from io import StringIO
import json
from pathlib import Path

import pytest
from rich.console import Console

from irsnapshot.models import InvestigationReport, SystemSnapshot


def report_for(data):
    from irsnapshot.analyzers.network import correlate_network
    from irsnapshot.analyzers.process_tree import build_process_tree
    from irsnapshot.correlation.timeline import build_timeline
    from irsnapshot.models import AnalysisResult
    snapshot = SystemSnapshot.model_validate(data)
    analysis = AnalysisResult(snapshot_id=snapshot.snapshot_id, ruleset_version='1.0.0', complete=True,
        process_tree=build_process_tree(snapshot.processes), network_links=correlate_network(snapshot),
        timeline=build_timeline(snapshot))
    return InvestigationReport(snapshot=snapshot, analysis=analysis)


def test_json_roundtrip_no_clobber_and_explicit_overwrite(snapshot_data, tmp_path):
    from irsnapshot.reporting.json_report import write_json_report
    report = report_for(snapshot_data)
    path = tmp_path / 'analysis.json'
    write_json_report(report, path)
    assert InvestigationReport.model_validate_json(path.read_bytes()) == report
    path.write_text('existing evidence')
    with pytest.raises(FileExistsError): write_json_report(report, path)
    assert path.read_text() == 'existing evidence'
    write_json_report(report, path, overwrite=True)
    assert json.loads(path.read_text())['snapshot'] == report.snapshot.model_dump(mode='json')
    assert sorted(p.name for p in tmp_path.iterdir()) == ['analysis.json']


def test_failed_publication_and_size_limit_preserve_destination(snapshot_data, tmp_path, monkeypatch):
    from irsnapshot.reporting import json_report
    import irsnapshot.storage as storage
    report = report_for(snapshot_data)
    path = tmp_path / 'out.json'
    path.write_text('original')
    def fail(*args): raise OSError('publication unavailable')
    monkeypatch.setattr(storage.os, 'replace', fail)
    with pytest.raises(OSError): json_report.write_json_report(report, path, overwrite=True)
    assert path.read_text() == 'original'
    assert list(tmp_path.iterdir()) == [path]
    monkeypatch.setattr(json_report, 'MAX_REPORT_BYTES', 5)
    with pytest.raises(ValueError, match='size limit'):
        json_report.write_json_report(report, path, overwrite=True)
    assert path.read_text() == 'original'


def test_report_revalidation_prevents_output(snapshot_data, tmp_path):
    from irsnapshot.reporting.json_report import write_json_report
    report = report_for(snapshot_data)
    report.snapshot.processes[0].pid = -1
    path = tmp_path / 'out.json'
    with pytest.raises(ValueError): write_json_report(report, path)
    assert not path.exists()


def test_console_literal_controls_coverage_and_no_findings(snapshot_data):
    from irsnapshot.reporting.console import render_console
    snapshot_data['system']['hostname'] = '[link=https://evil.invalid]host[/link]\x1b[2J\rBAD'
    report = report_for(snapshot_data)
    output = StringIO()
    render_console(report, Console(file=output, width=150, color_system=None))
    text = output.getvalue()
    assert '[link=https://evil.invalid]host[/link]\\x1b[2J\\rBAD' in text
    assert '\x1b' not in text and '\r' not in text
    for name in ['system', 'processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence']:
        assert name in text
    assert 'No findings' in text and 'clean host' in text and 'complete coverage' in text
    assert 'UTC' in text and 'pid_match' in text and 'Processes' in text


def test_console_no_system_and_partial_tree(snapshot_data):
    from irsnapshot.reporting.console import render_console
    snapshot_data['system'] = None
    run = next(r for r in snapshot_data['collector_runs'] if r['collector'] == 'system')
    run.update(status='failed', item_count=0, issues=[dict(collector='system', category='unavailable', message='No access', observed_at=run['finished_at'])])
    report = report_for(snapshot_data)
    # A report can contain a valid partial tree supplied by another producer.
    report.analysis.process_tree.nodes.clear()
    report.analysis.process_tree.root_ids.clear()
    output = StringIO()
    render_console(report, Console(file=output, width=120, color_system=None))
    assert 'System information unavailable' in output.getvalue()
    assert 'failed' in output.getvalue() and 'No access' in output.getvalue()
    assert 'not represented in tree' in output.getvalue()


def test_literal_finding_evidence_and_issue_rendering(snapshot_data):
    from irsnapshot.reporting.console import render_console
    from irsnapshot.models import AnalysisIssue, EvidenceItem, Finding
    from irsnapshot.severity import Severity
    from uuid import UUID
    report = report_for(snapshot_data)
    process = report.snapshot.processes[0]
    payload = '[red]evidence[/red]\x1b]8;;https://evil.invalid\x07'
    report.analysis.findings = [Finding(finding_id=UUID(int=8888), rule_id='X001', title=payload,
        severity=Severity.HIGH, description=payload, artifact_ids=[process.artifact_id],
        evidence=[EvidenceItem(artifact_id=process.artifact_id, field=payload, value=payload, explanation=payload)])]
    report.analysis.complete = False
    report.analysis.issues = [AnalysisIssue(component=payload, message=payload)]
    output = StringIO()
    render_console(report, Console(file=output, width=160, color_system=None))
    text = output.getvalue()
    assert '[red]evidence[/red]' in text and '\\x1b' in text
    assert '\x1b' not in text and '\x07' not in text
    assert 'INCOMPLETE' in text and 'high=1' in text


def test_report_publication_no_clobber_competing_writers(snapshot_data, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from irsnapshot.reporting.json_report import write_json_report
    report = report_for(snapshot_data)
    path = tmp_path / 'race.json'
    def write(_):
        try:
            write_json_report(report, path)
            return True
        except FileExistsError:
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(write, range(4)))
    assert outcomes.count(True) == 1
    assert InvestigationReport.model_validate_json(path.read_bytes()) == report
    assert list(tmp_path.iterdir()) == [path]


def test_successful_empty_inventories_show_ok_coverage(snapshot_data):
    from irsnapshot.reporting.console import render_console
    for name in ['processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence']:
        snapshot_data[name] = []
    for run in snapshot_data['collector_runs']:
        if run['collector'] != 'system':
            run.update(status='ok', item_count=0, issues=[])
    output = StringIO()
    render_console(report_for(snapshot_data), Console(file=output, width=160, color_system=None))
    text = output.getvalue()
    assert 'processes: ok; 0 items' in text and 'network: ok; 0 items' in text
    assert 'No network items captured; see collection status for coverage.' in text


def test_json_unicode_missing_parent_and_no_clobber_symlink(snapshot_data, tmp_path):
    from irsnapshot.reporting.json_report import write_json_report
    snapshot_data['system']['hostname'] = '实验-LAB'
    report = report_for(snapshot_data)
    with pytest.raises(FileNotFoundError): write_json_report(report, tmp_path / 'missing' / 'report.json')
    path = tmp_path / 'real.json'
    write_json_report(report, path)
    assert '实验-LAB' in path.read_text(encoding='utf-8')
    original = path.read_bytes()
    alias = tmp_path / 'alias.json'
    alias.symlink_to(path)
    with pytest.raises(FileExistsError): write_json_report(report, alias)
    assert path.read_bytes() == original and alias.is_symlink()


def test_correlations_show_literal_process_names_pids_and_plain_ids(snapshot_data):
    from irsnapshot.reporting.console import render_console
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import EvidenceItem, Finding
    from irsnapshot.severity import Severity
    from uuid import UUID
    snapshot_data['processes'][0]['name'] = '[red]owner[/red]\x1b[2J'
    report = report_for(snapshot_data)
    process = report.snapshot.processes[0]
    report.analysis.findings = [Finding(finding_id=UUID(int=8889), rule_id='X001', title='Owner mapping',
        severity=Severity.LOW, description='Synthetic mapping', artifact_ids=[process.artifact_id],
        evidence=[EvidenceItem(artifact_id=process.artifact_id, field='name', value=process.name, explanation='Captured process')])]
    report.analysis.finding_context = correlate_findings(report.analysis.findings, report.analysis.process_tree, report.analysis.network_links)
    output = StringIO()
    render_console(report, Console(file=output, width=240, color_system=None))
    text = output.getvalue()
    assert f'Processes: [red]owner[/red]\\x1b[2J (PID {process.pid}; {process.artifact_id})' in text
    assert f'owner: [red]owner[/red]\\x1b[2J (PID {process.pid}; {process.artifact_id})' in text
    assert "UUID('" not in text and '\x1b' not in text
