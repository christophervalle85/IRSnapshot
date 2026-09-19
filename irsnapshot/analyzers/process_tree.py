"""Deterministic parent/child associations from a single process inventory."""
from uuid import UUID

from irsnapshot.models import ProcessArtifact, ProcessNode, ProcessTree


def build_process_tree(processes: list[ProcessArtifact]) -> ProcessTree:
    """Build a forest, preserving orphans and marking unverified/PID-reuse links.

    Creation times can disprove a parent link; they cannot prove historical identity.
    No missing parent is fabricated and the source records are never changed.
    """
    records = sorted((ProcessArtifact.model_validate(p) for p in processes), key=lambda p: (p.pid, p.artifact_id.int))
    by_pid = {p.pid: p for p in records}
    by_id = {p.artifact_id: p for p in records}
    if len(by_pid) != len(records) or len(by_id) != len(records):
        raise ValueError('Process PIDs and artifact IDs must be unique')
    nodes = {p.artifact_id: _node_for(p, by_pid) for p in records}
    _break_cycles(nodes, by_id)
    for node in nodes.values():
        if node.parent_id is not None:
            nodes[node.parent_id].child_ids.append(node.process_id)
    roots = [n.process_id for n in nodes.values() if n.parent_id is None]
    return ProcessTree(nodes=list(nodes.values()), root_ids=roots)


def _node_for(process: ProcessArtifact, by_pid: dict[int, ProcessArtifact]) -> ProcessNode:
    node = ProcessNode(process_id=process.artifact_id, parent_status='root')
    if process.pid == 0 or process.ppid is None or process.ppid == process.pid:
        return node
    parent = by_pid.get(process.ppid)
    if parent is None:
        node.parent_status = 'missing'
    elif parent.created_at is not None and process.created_at is not None:
        if parent.created_at > process.created_at:
            node.parent_status = 'newer_parent'
        else:
            node.parent_id, node.parent_status = parent.artifact_id, 'linked'
    else:
        node.parent_id, node.parent_status = parent.artifact_id, 'unverified'
    return node


def _break_cycles(nodes: dict[UUID, ProcessNode], records: dict[UUID, ProcessArtifact]) -> None:
    """Walk parent chains iteratively; detach the lowest PID in each cycle."""
    complete: set[UUID] = set()
    for start in nodes:
        path: list[UUID] = []
        position: dict[UUID, int] = {}
        current: UUID | None = start
        while current is not None and current not in complete:
            if current in position:
                cycle = path[position[current]:]
                detached = min(cycle, key=lambda ident: (records[ident].pid, ident.int))
                nodes[detached].parent_id = None
                nodes[detached].parent_status = 'cycle_broken'
                break
            position[current] = len(path)
            path.append(current)
            current = nodes[current].parent_id
        complete.update(path)
