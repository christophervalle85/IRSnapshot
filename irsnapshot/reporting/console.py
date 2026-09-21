"""Literal, control-safe console evidence with explicit collection coverage."""
import json

from rich.console import Console
from rich.text import Text

from irsnapshot.models import InvestigationReport
from irsnapshot.reporting.process_tree import render_process_tree, safe_text
from irsnapshot.severity import Severity


def render_console(report: InvestigationReport, console: Console) -> None:
    """Present validated evidence, never interpret evidence as Rich markup/links."""
    report = InvestigationReport.model_validate(report)
    snapshot, analysis = report.snapshot, report.analysis

    def line(value: object = '') -> None:
        console.print(Text(safe_text(str(value))))

    line(f'IRSnapshot {snapshot.snapshot_id}')
    line(f'Collected {snapshot.started_at.isoformat()} to {snapshot.finished_at.isoformat()} (UTC)')
    if snapshot.system is None:
        line('System information unavailable')
    else:
        system = snapshot.system
        line(f'Host: {system.hostname or "unavailable"} | Windows: {system.windows_version or "unavailable"} | Architecture: {system.architecture or "unavailable"}')
        line(f'Collector identity: {system.collector_username or "unavailable"}; SID: {system.collector_sid or "unavailable"}; elevated: {system.elevated}')
    line('Collection coverage')
    for run in sorted(snapshot.collector_runs, key=lambda run: run.collector.value):
        line(f'  {run.collector.value}: {run.status.value}; {run.item_count} items; scope: {json.dumps(run.scope, ensure_ascii=False)}')
        for issue in sorted(run.issues, key=lambda item: (item.observed_at, item.category, item.field or '', item.message)):
            line(f'    {issue.category}: {issue.message}; field={issue.field}; target={issue.target}; artifact={issue.artifact_id}')
    line(f'Analysis: {"complete" if analysis.complete else "INCOMPLETE"}; ruleset {analysis.ruleset_version}')
    for issue in analysis.issues:
        line(f'  {issue.component} {issue.rule_id or ""}: {issue.message}')
    counts = {severity: sum(f.severity == severity for f in analysis.findings) for severity in Severity}
    line('Findings: ' + ', '.join(f'{severity.value}={counts[severity]}' for severity in reversed(Severity)))
    if not analysis.findings:
        line('No findings. This does not imply a clean host or complete coverage; only supported rules and available evidence were evaluated.')
    contexts = {context.finding_id: context for context in analysis.finding_context}
    process_by_id = {process.artifact_id: process for process in snapshot.processes}

    def process_labels(identifiers) -> str:
        return ', '.join(
            f'{process_by_id[ident].name or "unknown"} (PID {process_by_id[ident].pid}; {ident})'
            for ident in identifiers
        ) or 'none'

    for finding in analysis.findings:
        line(f'{finding.rule_id} [{finding.severity.value}] {finding.title} ({finding.finding_id})')
        line(f'  {finding.description}')
        line(f'  Artifacts: {", ".join(map(str, finding.artifact_ids))}; PIDs: {finding.pids}')
        for evidence in finding.evidence:
            line(f'  {evidence.artifact_id} {evidence.field} = {json.dumps(evidence.value, ensure_ascii=False)}; {evidence.explanation}')
        context = contexts.get(finding.finding_id)
        if context:
            line('  Correlation only (associations, not additional findings)')
            line(f'    Processes: {process_labels(context.process_ids)}')
            line(f'    Ancestors: {process_labels(context.ancestor_ids)}')
            line(f'    Children: {process_labels(context.child_ids)}')
            line(f'    Connections: {", ".join(map(str, context.connection_ids)) or "none"}')
    line('Process ancestry retains uncertain parent statuses; correlations do not inherit severity.')
    represented = {node.process_id for node in analysis.process_tree.nodes}
    processes = [process for process in snapshot.processes if process.artifact_id in represented]
    console.print(render_process_tree(analysis.process_tree, processes))
    for process in sorted(snapshot.processes, key=lambda item: (item.pid, item.artifact_id.int)):
        if process.artifact_id not in represented:
            line(f'  {process.name or "unknown"} (PID {process.pid}): not represented in tree')
    line('Network ownership (snapshot PID associations, not historical proof)')
    connections = {connection.artifact_id: connection for connection in snapshot.network}
    if not connections:
        line('  No network items captured; see collection status for coverage.')
    for link in analysis.network_links:
        connection = connections[link.connection_id]
        remote = f'{connection.remote.address}:{connection.remote.port}' if connection.remote else 'none'
        owner = process_labels([link.process_id]) if link.process_id is not None else 'unavailable'
        line(f'  {link.connection_id}: {connection.protocol} {connection.local.address}:{connection.local.port} -> {remote}; owning PID={connection.owning_pid}; {link.status}; owner: {owner}')
    linked = {link.connection_id for link in analysis.network_links}
    for ident in sorted(connections.keys() - linked, key=lambda item: item.int):
        line(f'  {ident}: ownership association unavailable')
    line(f'Persistence inventory: {len(snapshot.persistence)} entries; {len(snapshot.scheduled_tasks)} scheduled tasks; {len(snapshot.services)} services')
    line('Factual timeline (UTC; reported times and observed collection boundaries)')
    for event in analysis.timeline:
        line(f'  {event.timestamp.isoformat()} [{event.basis}] {event.kind}: {event.description}')
    line('A point-in-time snapshot cannot reconstruct exited processes or past connections. Missing evidence and unsupported command grammar limit matching.')
