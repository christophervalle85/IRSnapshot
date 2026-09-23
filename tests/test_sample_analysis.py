"""Published synthetic walkthroughs exercise the advertised rule and coverage outcomes."""
from pathlib import Path

from irsnapshot.storage import load_snapshot


SAMPLES = Path(__file__).resolve().parents[1] / 'samples'
REVIEW_RULE_IDS = {
    'IRS-P001', 'IRS-P002', 'IRS-P003', 'IRS-P004', 'IRS-P005',
    'IRS-P006', 'IRS-P007', 'IRS-P008', 'IRS-P009', 'IRS-P010',
    'IRS-R001', 'IRS-R002', 'IRS-R003',
}


def test_review_walkthrough_exercises_all_thirteen_rules_without_duplicate_task_findings():
    snapshot = load_snapshot(SAMPLES / 'review.snapshot.json')
    from irsnapshot.analyzers.engine import analyze_snapshot
    result = analyze_snapshot(snapshot)
    assert result.complete is True
    assert {finding.rule_id for finding in result.findings} == REVIEW_RULE_IDS
    assert len(result.findings) == 13
    assert result.issues == []
    assert len([finding for finding in result.findings if finding.rule_id == 'IRS-R002']) == 1


def test_partial_walkthrough_keeps_findings_without_claiming_missing_command_evidence():
    snapshot = load_snapshot(SAMPLES / 'partial.snapshot.json')
    from irsnapshot.analyzers.engine import analyze_snapshot
    result = analyze_snapshot(snapshot)
    assert snapshot.system is None
    assert snapshot.network == []
    assert any(run.status == 'failed' for run in snapshot.collector_runs)
    assert result.complete is True
    assert {finding.rule_id for finding in result.findings} == REVIEW_RULE_IDS - {'IRS-P001', 'IRS-P002'}
    assert len(result.findings) == 11
    assert not any(event.kind == 'boot' for event in result.timeline)
