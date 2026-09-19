"""Rich process-tree rendering with literal, control-safe artifact labels."""
from rich.text import Text
from rich.tree import Tree

from irsnapshot.models import ProcessArtifact, ProcessTree


def safe_text(value: str) -> str:
    """Make terminal control and invisible formatting characters visible."""
    return ''.join(char if char.isprintable() else char.encode('unicode_escape').decode('ascii') for char in value)


def render_process_tree(tree: ProcessTree, processes: list[ProcessArtifact]) -> Tree:
    tree = ProcessTree.model_validate(tree)
    records = [ProcessArtifact.model_validate(process) for process in processes]
    by_id = {process.artifact_id: process for process in records}
    nodes = {node.process_id: node for node in tree.nodes}
    if len(by_id) != len(records) or set(by_id) != set(nodes):
        raise ValueError('Tree and process inventory must contain exactly the same unique artifacts')
    root = Tree(Text('Processes'))
    pending = [(ident, root) for ident in reversed(tree.root_ids)]
    while pending:
        ident, parent = pending.pop()
        process, node = by_id[ident], nodes[ident]
        label = f'{safe_text(process.name or "unknown")} (PID {process.pid})'
        if node.parent_status not in ('root', 'linked'):
            label += f' [{node.parent_status}; reported PPID {process.ppid}]'
        branch = parent.add(Text(label))
        pending.extend((child, branch) for child in reversed(node.child_ids))
    return root
