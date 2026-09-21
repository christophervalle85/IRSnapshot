"""Deterministic analysis and hostile evaluator boundaries."""
from copy import deepcopy
from uuid import UUID

import pytest

from irsnapshot.models import EvidenceItem, Finding, SystemSnapshot
from irsnapshot.severity import Severity


def api():
    from irsnapshot.analyzers.engine import analyze_snapshot
    from irsnapshot.rules.base import Rule
    return analyze_snapshot, Rule


def finding(context, *, rule_id='X001', field='name', value='test'):
    process = context.snapshot.processes[0]
    return Finding(finding_id=UUID(int=999), rule_id=rule_id, title='Test rule',
                   severity=Severity.LOW, description='Synthetic review; may be benign.',
                   artifact_ids=[process.artifact_id], pids=[process.pid],
                   evidence=[EvidenceItem(artifact_id=process.artifact_id, field=field,
                                          value=value, explanation='Synthetic evidence')])


def test_all_defaults_and_benign_result(snapshot_data):
    analyze, _ = api()
    from irsnapshot.rules import DEFAULT_RULES
    assert [r.rule_id for r in DEFAULT_RULES] == [f'IRS-P{i:03}' for i in range(1, 11)] + ['IRS-R001', 'IRS-R002', 'IRS-R003']
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    before = snapshot.model_dump_json()
    result = analyze(snapshot)
    assert result.complete and result.findings == [] and result.ruleset_version == '1.0.0'
    assert len(result.process_tree.nodes) == len(snapshot.processes)
    assert len(result.network_links) == len(snapshot.network)
    assert result.timeline
    assert snapshot.model_dump_json() == before


def test_isolated_mutation_failure_survives_and_source_unchanged(snapshot_data):
    analyze, Rule = api()
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    before = snapshot.model_dump_json()
    def poison(context):
        context.snapshot.processes.clear()
        context.tree.nodes.clear()
        context.network_links.clear()
        raise RuntimeError('secret command should not leak')
    good = Rule('X001', 'Test rule', Severity.LOW, lambda c: [finding(c)])
    bad = Rule('X000', 'Broken', Severity.HIGH, poison)
    result = analyze(snapshot, [bad, good])
    assert not result.complete and len(result.findings) == 1
    assert result.issues[0].rule_id == 'X000'
    assert 'RuntimeError' in result.issues[0].message
    assert 'secret' not in result.issues[0].message
    assert len(result.process_tree.nodes) == len(snapshot.processes)
    assert snapshot.model_dump_json() == before


@pytest.mark.parametrize('problem', ['unknown_artifact', 'wrong_rule', 'wrong_severity', 'wrong_title', 'wrong_pid', 'none', 'dict'])
def test_malformed_rule_is_an_issue_and_other_rules_continue(snapshot_data, problem):
    analyze, Rule = api()
    def broken(c):
        f = finding(c)
        if problem == 'unknown_artifact':
            f.artifact_ids = [UUID(int=1)]
            f.evidence[0].artifact_id = UUID(int=1)
        elif problem == 'wrong_rule': f.rule_id = 'OTHER'
        elif problem == 'wrong_severity': f.severity = Severity.CRITICAL
        elif problem == 'wrong_title': f.title = 'Wrong'
        elif problem == 'wrong_pid': f.pids = [999999]
        elif problem == 'none': return None
        elif problem == 'dict': return [f.model_dump()]
        return [f]
    good = Rule('X002', 'Test rule', Severity.LOW, lambda c: [finding(c, rule_id='X002')])
    result = analyze(SystemSnapshot.model_validate(snapshot_data), [Rule('X001', 'Test rule', Severity.LOW, broken), good])
    assert not result.complete
    assert [f.rule_id for f in result.findings] == ['X002']
    assert [i.rule_id for i in result.issues] == ['X001']


def test_dedup_preserves_distinct_evidence_and_is_reproducible(snapshot_data):
    analyze, Rule = api()
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    target_id = snapshot.processes[0].artifact_id
    def evaluate(c):
        # Select by stable identity even when the input is reordered.
        c.snapshot.processes.sort(key=lambda p: p.artifact_id != target_id)
        a = finding(c)
        b = finding(c, field='command_line', value=['a', 'b'])
        b.finding_id = UUID(int=123)
        return [b, a, deepcopy(a)]
    rule = Rule('X001', 'Test rule', Severity.LOW, evaluate)
    first = analyze(snapshot, [rule])
    snapshot.processes.reverse()
    snapshot.network.reverse()
    snapshot.collector_runs.reverse()
    second = analyze(snapshot, [rule])
    assert first.model_dump_json() == second.model_dump_json()
    assert len(first.findings) == 1 and len(first.findings[0].evidence) == 2
    from irsnapshot.rules.base import finding_id
    assert first.findings[0].finding_id == finding_id(snapshot.snapshot_id, 'X001', [target_id])


def test_duplicate_rule_configuration_rejected(snapshot_data):
    analyze, Rule = api()
    rule = Rule('X001', 'Test rule', Severity.LOW, lambda c: [])
    with pytest.raises(ValueError, match='Duplicate rule'):
        analyze(SystemSnapshot.model_validate(snapshot_data), [rule, rule])


@pytest.mark.parametrize('exception', [KeyboardInterrupt, SystemExit])
def test_interrupts_are_not_rule_issues(snapshot_data, exception):
    analyze, Rule = api()
    def stop(c): raise exception()
    with pytest.raises(exception):
        analyze(SystemSnapshot.model_validate(snapshot_data), [Rule('X001', 'Test rule', Severity.LOW, stop)])


def test_snapshot_revalidated(snapshot_data):
    analyze, _ = api()
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    snapshot.processes[0].pid = -1
    with pytest.raises(ValueError): analyze(snapshot)


def test_structural_failure_is_fatal_not_clean(snapshot_data, monkeypatch):
    analyze, _ = api()
    import irsnapshot.analyzers.engine as engine
    def broken(*a): raise RuntimeError('boom')
    monkeypatch.setattr(engine, 'build_process_tree', broken)
    with pytest.raises(engine.AnalysisError, match='process tree'):
        analyze(SystemSnapshot.model_validate(snapshot_data))


def test_rule_order_and_severity_order_are_stable(snapshot_data):
    analyze, Rule = api()
    def make(rule_id, severity):
        def evaluate(c):
            f = finding(c, rule_id=rule_id)
            f.severity = severity
            return [f]
        return Rule(rule_id, 'Test rule', severity, evaluate)
    rules = [make('X003', Severity.HIGH), make('X001', Severity.LOW), make('X002', Severity.HIGH)]
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    first = analyze(snapshot, rules)
    second = analyze(snapshot, rules[::-1])
    assert first == second
    assert [f.rule_id for f in first.findings] == ['X002', 'X003', 'X001']


def test_rule_batch_is_atomic_if_later_finding_invalid(snapshot_data):
    analyze, Rule = api()
    def mixed(c):
        good = finding(c)
        invalid = deepcopy(good)
        invalid.title = ''
        return [good, invalid]
    result = analyze(SystemSnapshot.model_validate(snapshot_data), [Rule('X001', 'Test rule', Severity.LOW, mixed)])
    assert result.findings == [] and not result.complete


def test_malformed_rule_metadata_isolated(snapshot_data):
    analyze, Rule = api()
    broken = Rule('X001', 'Test rule', Severity.LOW, None)
    result = analyze(SystemSnapshot.model_validate(snapshot_data), [broken])
    assert not result.complete and result.issues[0].rule_id == 'X001'


def test_collection_failure_does_not_make_analysis_incomplete(snapshot_data):
    analyze, _ = api()
    run = next(r for r in snapshot_data['collector_runs'] if r['collector'] == 'network')
    run.update(status='partial', issues=[dict(collector='network', category='unavailable', message='Some information missing', observed_at=run['finished_at'])])
    result = analyze(SystemSnapshot.model_validate(snapshot_data))
    assert result.complete and result.issues == []


def test_default_review_analysis_is_identical_after_inventory_reordering():
    from pathlib import Path
    from irsnapshot.storage import load_snapshot
    analyze, _ = api()
    snapshot = load_snapshot(Path(__file__).resolve().parents[1] / 'samples/review.snapshot.json')
    first = analyze(snapshot)
    for field in ['processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence', 'collector_runs']:
        getattr(snapshot, field).reverse()
    snapshot.path_context.known_paths.reverse()
    snapshot.path_context.environment.reverse()
    assert analyze(snapshot).model_dump_json() == first.model_dump_json()
    assert len(first.findings) == 13
