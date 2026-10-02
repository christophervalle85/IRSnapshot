"""Standalone analyst reporting and safe publication contracts."""
import json
from html.parser import HTMLParser
from pathlib import Path
from uuid import UUID

import pytest

from irsnapshot.analyzers.engine import analyze_snapshot
from irsnapshot.models import AnalysisIssue, EvidenceItem, Finding, InvestigationReport, SystemSnapshot
from irsnapshot.severity import Severity
from irsnapshot.storage import load_snapshot

ROOT = Path(__file__).resolve().parents[1]


def report_for(snapshot):
    return InvestigationReport(snapshot=snapshot, analysis=analyze_snapshot(snapshot))


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.ids = []
        self.links = []
        self.text = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attrs = dict(attrs)
        if 'id' in attrs:
            self.ids.append(attrs['id'])
        if tag == 'a':
            self.links.append(attrs.get('href', ''))
        assert not any(key.startswith('on') for key in attrs)
        assert not any(key in attrs for key in ['src', 'srcdoc'])

    def handle_data(self, data):
        self.text.append(data)


@pytest.mark.parametrize('sample,partial,findings', [('benign', False, False), ('review', False, True), ('partial', True, True)])
def test_sample_report_is_complete_static_and_deterministic(sample, partial, findings):
    from irsnapshot.reporting.html_report import render_html
    report = report_for(load_snapshot(ROOT / f'samples/{sample}.snapshot.json'))
    rendered = render_html(report)
    assert rendered == render_html(report)
    document = Document(rendered)
    text = ''.join(document.text)
    assert all(link.startswith('#') and link[1:] in document.ids for link in document.links)
    assert len(document.ids) == len(set(document.ids))
    assert not {'script', 'iframe', 'object', 'embed', 'link', 'img'} & set(document.tags)
    assert {'nav', 'main', 'section', 'details', 'summary', 'table', 'style'} <= set(document.tags)
    for label in ['Collection coverage', 'System and identity', 'Findings', 'Process ancestry', 'Referenced processes', 'Network ownership', 'Persistence', 'Factual timeline', 'Collection and analysis issues', 'Raw evidence', 'UTC']:
        assert label in text
    assert ('Partial investigation' in text) == partial
    assert ('No findings' in text) != findings
    if not findings:
        assert 'malware clearance' in text
    for name in ['system', 'processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence']:
        assert name in text


def test_untrusted_fields_issues_and_raw_task_service_evidence_are_literal(snapshot_data):
    from irsnapshot.reporting.html_report import render_html
    payload = '<script>alert(1)</script><img src="https://evil.invalid" onerror="x">'
    snapshot_data['system']['hostname'] = payload
    snapshot_data['processes'][0]['name'] = payload
    snapshot_data['processes'][0]['command_line'] = [payload, 'https://evil.invalid']
    for service in snapshot_data['services']:
        service['command'] = payload
    for task in snapshot_data['scheduled_tasks']:
        task['actions'][0]['arguments'] = payload
    report = report_for(SystemSnapshot.model_validate(snapshot_data))
    process = report.snapshot.processes[0]
    report.analysis.findings = [Finding(finding_id=UUID(int=999), rule_id=payload, title=payload,
        severity=Severity.HIGH, description=payload, artifact_ids=[process.artifact_id],
        evidence=[EvidenceItem(artifact_id=process.artifact_id, field=payload, value=payload, explanation=payload)])]
    report.analysis.finding_context = []
    report.analysis.complete = False
    report.analysis.issues = [AnalysisIssue(component=payload, message=payload)]
    rendered = render_html(report)
    document = Document(rendered)
    assert payload in ''.join(document.text)
    assert '<script>' not in rendered and '<img ' not in rendered
    assert all(link.startswith('#') for link in document.links)
    assert '&lt;script&gt;' in rendered
    assert 'Incomplete' in ''.join(document.text)
    assert json.dumps(report.snapshot.scheduled_tasks[0].model_dump(mode='json'), ensure_ascii=False, indent=2) in ''.join(document.text)


def test_severity_order_uncertainty_and_unassociated_network(snapshot_data):
    from irsnapshot.reporting.html_report import render_html
    report = report_for(SystemSnapshot.model_validate(snapshot_data))
    process = report.snapshot.processes[0]
    report.analysis.findings = [Finding(finding_id=UUID(int=i), rule_id=f'T{i}', title=title,
        severity=severity, description='Synthetic', artifact_ids=[process.artifact_id],
        evidence=[EvidenceItem(artifact_id=process.artifact_id, field='name', value='x', explanation='Synthetic')])
        for i, title, severity in [(1, 'Low priority fixture', Severity.LOW), (2, 'Critical priority fixture', Severity.CRITICAL)]]
    report.analysis.finding_context = []
    report.analysis.network_links = []
    report.analysis.process_tree.nodes = []
    report.analysis.process_tree.root_ids = []
    text = ''.join(Document(render_html(report)).text)
    assert text.index('Critical priority fixture') < text.index('Low priority fixture')
    assert 'not represented in tree' in text
    assert 'association unavailable' in text
    assert report.snapshot.network[0].local.address in text
    assert 'reported' in text and 'observed' in text


def test_deep_ancestry_renders_iteratively(snapshot_data, process_factory):
    from irsnapshot.reporting.html_report import render_html
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    snapshot.processes = [process_factory(i, i - 1 if i else None, f'process-{i}') for i in range(1300)]
    run = next(run for run in snapshot.collector_runs if run.collector == 'processes')
    run.item_count = 1300
    rendered = render_html(report_for(snapshot))
    assert 'process-1299' in rendered
    assert 'Depth 1299' in rendered


def test_html_atomic_no_clobber_size_validation_and_failure(snapshot_data, tmp_path, monkeypatch):
    from irsnapshot.reporting import html_report
    import irsnapshot.storage as storage
    report = report_for(SystemSnapshot.model_validate(snapshot_data))
    output = tmp_path / 'report.html'
    html_report.write_html_report(report, output)
    original = output.read_bytes()
    with pytest.raises(FileExistsError):
        html_report.write_html_report(report, output)
    def fail(*args):
        raise OSError('publication unavailable')
    monkeypatch.setattr(storage.os, 'replace', fail)
    with pytest.raises(OSError):
        html_report.write_html_report(report, output, overwrite=True)
    assert output.read_bytes() == original
    monkeypatch.setattr(html_report, 'MAX_REPORT_BYTES', 50)
    with pytest.raises(ValueError, match='size limit'):
        html_report.write_html_report(report, output, overwrite=True)
    assert output.read_bytes() == original
    report.snapshot.processes[0].pid = -1
    with pytest.raises(ValueError):
        html_report.render_html(report)
    assert list(tmp_path.iterdir()) == [output]


def test_empty_and_unavailable_inventory_states(snapshot_data):
    from irsnapshot.reporting.html_report import render_html
    for name in ['processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence']:
        snapshot_data[name] = []
        run = next(r for r in snapshot_data['collector_runs'] if r['collector'] == name)
        run.update(item_count=0, status='ok', issues=[])
    snapshot_data['system'] = None
    run = next(r for r in snapshot_data['collector_runs'] if r['collector'] == 'system')
    run.update(item_count=0, status='failed', issues=[dict(collector='system', category='unavailable', message='Missing system', observed_at=run['finished_at'])])
    text = ''.join(Document(render_html(report_for(SystemSnapshot.model_validate(snapshot_data)))).text)
    assert 'System information unavailable' in text
    assert 'No network items captured' in text and 'No processes captured' in text
    assert 'Missing system' in text and 'Partial investigation' in text


@pytest.mark.parametrize('status', ['failed', 'partial'])
def test_empty_incomplete_network_exposes_status_and_coverage_link(status):
    from irsnapshot.reporting.html_report import render_html
    report = report_for(load_snapshot(ROOT / 'samples/partial.snapshot.json'))
    assert not report.snapshot.network
    run = next(run for run in report.snapshot.collector_runs if run.collector == 'network')
    run.status = status
    rendered = render_html(report)
    network = rendered.split('<section id="network">', 1)[1].split('</section>', 1)[0]
    assert 'Source status:' in ''.join(Document(network).text)
    assert status in ''.join(Document(network).text)
    assert '#coverage-network' in Document(network).links
    assert 'coverage-network' in Document(rendered).ids
