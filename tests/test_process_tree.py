"""Tree construction must retain uncertain relationships without inventing parents."""
from datetime import UTC, datetime
from io import StringIO
from uuid import UUID

import pytest
from pydantic import ValidationError
from rich.console import Console


def build(processes):
    from irsnapshot.analyzers.process_tree import build_process_tree
    return build_process_tree(processes)


def test_office_chain_has_reciprocal_links_and_stable_order(process_factory):
    parent = process_factory(1, name='explorer.exe')
    office = process_factory(2, 1, 'WINWORD.EXE')
    child = process_factory(3, 2, 'powershell.exe')
    tree = build([child, parent, office])
    assert tree.root_ids == [UUID(int=1001)]
    assert [node.process_id for node in tree.nodes] == [UUID(int=n) for n in (1001, 1002, 1003)]
    assert tree.nodes[1].parent_id == UUID(int=1001)
    assert tree.nodes[1].child_ids == [UUID(int=1003)]
    assert tree.nodes[2].parent_status == 'linked'
    assert tree == build([office, child, parent])
    assert child.ppid == 2


@pytest.mark.parametrize(('pid', 'ppid', 'status'), [(0, 2, 'root'), (2, 2, 'root'), (2, None, 'root'), (2, 99, 'missing')])
def test_roots_and_missing_parents_are_explicit(process_factory, pid, ppid, status):
    node = build([process_factory(pid, ppid)]).nodes[0]
    assert node.parent_id is None
    assert node.parent_status == status
    assert node.child_ids == []


def test_pid_zero_can_own_a_child(process_factory):
    tree = build([process_factory(0), process_factory(2, 0)])
    assert tree.nodes[1].parent_id == UUID(int=1000)


def test_parent_newer_than_child_is_rejected(process_factory):
    tree = build([process_factory(1, created_at=datetime(2026, 9, 17, 14, 2, tzinfo=UTC)), process_factory(2, 1)])
    assert tree.nodes[1].parent_id is None
    assert tree.nodes[1].parent_status == 'newer_parent'


@pytest.mark.parametrize('unknown', ['parent', 'child'])
def test_unknown_creation_keeps_link_but_marks_unverified(process_factory, unknown):
    parent, child = process_factory(1), process_factory(2, 1)
    (parent if unknown == 'parent' else child).created_at = None
    node = build([parent, child]).nodes[1]
    assert node.parent_id == parent.artifact_id
    assert node.parent_status == 'unverified'


def test_cycle_is_broken_at_smallest_pid_deterministically(process_factory):
    records = [process_factory(30, 10), process_factory(10, 20), process_factory(20, 30)]
    tree = build(records)
    assert tree.root_ids == [UUID(int=1010)]
    assert tree.nodes[0].parent_status == 'cycle_broken'
    assert tree.nodes[0].child_ids == [UUID(int=1030)]
    assert tree == build(list(reversed(records)))


def test_deep_chain_does_not_recurse(process_factory):
    tree = build([process_factory(pid, pid - 1 if pid else None) for pid in range(1800)])
    assert len(tree.nodes) == 1800
    assert tree.root_ids == [UUID(int=1000)]
    assert tree.nodes[-1].parent_id == UUID(int=2798)


def test_empty_tree_is_valid():
    tree = build([])
    assert tree.nodes == tree.root_ids == []


@pytest.mark.parametrize('duplicate', ['pid', 'id'])
def test_duplicate_identifiers_rejected(process_factory, duplicate):
    one, two = process_factory(1), process_factory(2)
    if duplicate == 'pid':
        two.pid = 1
    else:
        two.artifact_id = one.artifact_id
    with pytest.raises(ValueError):
        build([one, two])


def test_mutated_invalid_artifacts_are_revalidated(process_factory):
    record = process_factory(1)
    record.pid = -1
    with pytest.raises(ValidationError):
        build([record])


def test_rich_render_preserves_hierarchy_and_literal_names(process_factory):
    from irsnapshot.reporting.process_tree import render_process_tree
    records = [process_factory(1, name='explorer.exe'), process_factory(2, 1, 'WINWORD.EXE'),
               process_factory(3, 2, 'powershell.exe'), process_factory(4, 99, '[red]bad\x1b[2J\nname')]
    output = StringIO()
    Console(file=output, width=100, color_system=None).print(render_process_tree(build(records), records))
    shown = output.getvalue()
    assert shown.index('explorer.exe') < shown.index('WINWORD.EXE') < shown.index('powershell.exe')
    assert '└── powershell.exe' in shown
    assert '[red]bad' in shown
    assert '\x1b' not in shown
    assert 'missing' in shown


def test_render_fails_clearly_on_missing_process_record(process_factory):
    from irsnapshot.reporting.process_tree import render_process_tree
    tree = build([process_factory(1)])
    with pytest.raises(ValueError):
        render_process_tree(tree, [])
