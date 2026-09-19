"""PID associations retain missing owners and never propagate detection severity."""
from uuid import UUID
import pytest


def network_snapshot(data, owner, created='2026-09-17T14:00:00Z', observed='2026-09-17T14:05:00Z'):
    from irsnapshot.models import SystemSnapshot
    data['network'][0].update(owning_pid=owner, observed_at=observed)
    data['processes'][0]['created_at'] = created
    return SystemSnapshot.model_validate(data)


@pytest.mark.parametrize(('owner','created','status','matched'), [
    (400,'2026-09-17T14:00:00Z','pid_match',True),
    (None,'2026-09-17T14:00:00Z','owner_unavailable',False),
    (999,'2026-09-17T14:00:00Z','process_missing',False),
    (400,None,'pid_match',True),
])
def test_network_owner_resolution(snapshot_data, owner, created, status, matched):
    from irsnapshot.analyzers.network import correlate_network
    snapshot = network_snapshot(snapshot_data, owner, created)
    link = correlate_network(snapshot)[0]
    assert link.status == status
    assert link.process_id == (UUID(int=2) if matched else None)
    assert link.connection_id == UUID(int=3)


def test_network_rejects_process_created_after_connection_observation(snapshot_data):
    from irsnapshot.analyzers.network import correlate_network
    snapshot_data['processes'][0]['observed_at'] = '2026-09-17T14:05:09Z'
    snapshot = network_snapshot(snapshot_data, 400, created='2026-09-17T14:05:05Z')
    assert correlate_network(snapshot)[0].status == 'temporal_conflict'


def test_pid_zero_owner_is_not_unknown(snapshot_data):
    from irsnapshot.analyzers.network import correlate_network
    snapshot_data['processes'][0]['pid'] = 0
    assert correlate_network(network_snapshot(snapshot_data, 0))[0].status == 'pid_match'


def test_network_correlation_preserves_scoped_ipv6_evidence(snapshot_data):
    from irsnapshot.analyzers.network import correlate_network
    snapshot_data['network'][0].update(
        family='ipv6', local={'address': 'fe80::1234%7', 'port': 50000})
    snapshot = network_snapshot(snapshot_data, 400)
    before = snapshot.model_dump_json()
    assert correlate_network(snapshot)[0].process_id == UUID(int=2)
    assert snapshot.network[0].local.address == 'fe80::1234%7'
    assert snapshot.model_dump_json() == before


def finding(artifact_id, *, pid=400):
    from irsnapshot.models import Finding, EvidenceItem
    return Finding(finding_id=UUID(int=90), rule_id='TEST', title='Fixture', severity='low',
                   description='Synthetic review only', artifact_ids=[artifact_id], pids=[pid],
                   evidence=[EvidenceItem(artifact_id=artifact_id, field='name', value='fixture', explanation='test')])


def test_finding_context_links_ancestors_children_and_direct_network(process_factory):
    from irsnapshot.analyzers.process_tree import build_process_tree
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import NetworkProcessLink
    tree = build_process_tree([process_factory(1), process_factory(2,1), process_factory(3,2)])
    connections = [NetworkProcessLink(connection_id=UUID(int=50),process_id=UUID(int=1002),status='pid_match'),
                   NetworkProcessLink(connection_id=UUID(int=51),process_id=UUID(int=1003),status='pid_match')]
    original = finding(UUID(int=1002))
    result = correlate_findings([original],tree,connections)[0]
    assert result.process_ids == [UUID(int=1002)]
    assert result.ancestor_ids == [UUID(int=1001)]
    assert result.child_ids == [UUID(int=1003)]
    assert result.connection_ids == [UUID(int=50)]
    assert original.severity == 'low'
    assert original.artifact_ids == [UUID(int=1002)]


def test_connection_evidence_resolves_owner_but_pid_hint_alone_does_not(process_factory):
    from irsnapshot.analyzers.process_tree import build_process_tree
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import NetworkProcessLink
    tree = build_process_tree([process_factory(1)])
    links = [NetworkProcessLink(connection_id=UUID(int=50),process_id=UUID(int=1001),status='pid_match')]
    result = correlate_findings([finding(UUID(int=50))], tree, links)[0]
    assert result.process_ids == [UUID(int=1001)]
    # An artifact outside the tree may be service/persistence evidence; a PID hint isn't proof.
    result = correlate_findings([finding(UUID(int=77),pid=1)],tree,links)[0]
    assert result.process_ids == result.ancestor_ids == result.connection_ids == []


def test_unowned_direct_connection_remains_in_finding_context():
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import ProcessTree, NetworkProcessLink
    result = correlate_findings([finding(UUID(int=50))], ProcessTree(), [
        NetworkProcessLink(connection_id=UUID(int=50),status='process_missing')])[0]
    assert result.connection_ids == [UUID(int=50)]
    assert result.process_ids == []


def test_bad_link_endpoint_is_rejected():
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import ProcessTree, NetworkProcessLink
    with pytest.raises(ValueError):
        correlate_findings([], ProcessTree(), [NetworkProcessLink(connection_id=UUID(int=50),process_id=UUID(int=1001),status='pid_match')])


def test_connection_id_cannot_also_identify_a_process(process_factory):
    from irsnapshot.analyzers.process_tree import build_process_tree
    from irsnapshot.correlation.relationships import correlate_findings
    from irsnapshot.models import NetworkProcessLink
    tree = build_process_tree([process_factory(1), process_factory(2)])
    links = [NetworkProcessLink(connection_id=UUID(int=1001),
                                process_id=UUID(int=1002), status='pid_match')]
    with pytest.raises(ValueError, match='overlap'):
        correlate_findings([finding(UUID(int=1001))], tree, links)
