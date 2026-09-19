"""Join finding evidence to structural context without extending its verdict."""
from uuid import UUID

from irsnapshot.models import Finding, FindingContext, NetworkProcessLink, ProcessNode, ProcessTree


def correlate_findings(
    findings: list[Finding], tree: ProcessTree, links: list[NetworkProcessLink],
) -> list[FindingContext]:
    """Associate only artifact references; convenience PID hints are not evidence.

    Ancestors may cross unverified parent links: callers must retain the tree's
    parent_status when presenting that context. Relatives do not inherit severity.
    """
    tree = ProcessTree.model_validate(tree)
    nodes = {node.process_id: node for node in tree.nodes}
    links = [NetworkProcessLink.model_validate(link) for link in links]
    by_connection = {link.connection_id: link for link in links}
    findings = [Finding.model_validate(finding) for finding in findings]
    if len(by_connection) != len(links) or len({f.finding_id for f in findings}) != len(findings):
        raise ValueError('Connection and finding IDs must be unique')
    if nodes.keys() & by_connection.keys():
        raise ValueError('Process and connection artifact IDs must not overlap')
    if any(link.process_id is not None and link.process_id not in nodes for link in links):
        raise ValueError('Network link references a process outside the tree')
    output: list[FindingContext] = []
    for finding in sorted(findings, key=lambda f: f.finding_id.int):
        direct = set(finding.artifact_ids) & nodes.keys()
        connections = set(finding.artifact_ids) & by_connection.keys()
        direct.update(by_connection[c].process_id for c in connections if by_connection[c].process_id is not None)
        ancestors, children = _relatives(direct, nodes)
        connections.update(link.connection_id for link in links if link.process_id in direct)
        output.append(FindingContext(
            finding_id=finding.finding_id, process_ids=sorted(direct, key=lambda x: x.int),
            ancestor_ids=sorted(ancestors - direct, key=lambda x: x.int),
            child_ids=sorted(children - direct, key=lambda x: x.int),
            connection_ids=sorted(connections, key=lambda x: x.int),
        ))
    return output


def _relatives(direct: set[UUID], nodes: dict[UUID, ProcessNode]) -> tuple[set[UUID], set[UUID]]:
    ancestors: set[UUID] = set()
    children: set[UUID] = set()
    for ident in direct:
        children.update(nodes[ident].child_ids)
        parent = nodes[ident].parent_id
        while parent is not None and parent not in ancestors:
            ancestors.add(parent)
            parent = nodes[parent].parent_id
    return ancestors, children
