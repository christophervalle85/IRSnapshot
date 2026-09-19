"""Read-only demonstration of Milestone 2 APIs; install the package before use."""
import argparse
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from irsnapshot.analyzers.commands import parse_command_target, parse_process_command
from irsnapshot.analyzers.network import correlate_network
from irsnapshot.analyzers.paths import classify_path
from irsnapshot.analyzers.process_tree import build_process_tree
from irsnapshot.correlation.timeline import build_timeline
from irsnapshot.reporting.process_tree import render_process_tree, safe_text
from irsnapshot.storage import SnapshotValidationError, load_snapshot


def literal(value: str) -> Text:
    return Text(safe_text(value))


def main() -> int:
    parser = argparse.ArgumentParser(description='Interpret a saved snapshot offline without collecting or executing anything.')
    parser.add_argument('snapshot', type=Path, help='Path to a validated IRSnapshot JSON file')
    args = parser.parse_args()
    console = Console()
    try:
        snapshot = load_snapshot(args.snapshot)
    except (OSError, SnapshotValidationError) as exc:
        Console(stderr=True).print(literal(f'Cannot read snapshot: {exc}'))
        return 2

    hostname = snapshot.system.hostname if snapshot.system is not None else None
    console.print(literal(f'IRSnapshot — offline interpretation of {hostname or "unknown host"}'))
    console.print('No detection rules or malware verdicts are applied.')
    console.print(f'{len(snapshot.processes)} processes · {len(snapshot.network)} connections')
    console.print('Collection coverage: ' + ', '.join(
        f'{run.collector}: {run.status}' for run in sorted(snapshot.collector_runs, key=lambda item: item.collector)))
    console.print(render_process_tree(build_process_tree(snapshot.processes), snapshot.processes))

    console.print('\nProcess facts', style='bold')
    for process in sorted(snapshot.processes, key=lambda item: item.pid):
        facts = parse_process_command(process)
        console.print(literal(f'PID {process.pid}: {facts.executable_name or "unknown executable"}'))
        # A username is not an owner SID. Do not infer owner-scoped variables.
        if process.executable:
            path = classify_path(process.executable, snapshot.path_context)
            console.print(literal(f'  Path: {path.category} / {path.confidence} — {path.basis}'))
        else:
            console.print('  Path: unavailable')
        names = ', '.join(option.name for option in facts.host_options) or 'none recognized'
        console.print(literal(f'  Host options: {names}; {len(facts.payload)} remaining payload tokens'))
        for issue in facts.parse_issues:
            console.print(literal(f'  Parse limitation: {issue}'))

    table = Table(title='Network ownership associations')
    table.add_column('Connection')
    table.add_column('Process PID', no_wrap=True)
    table.add_column('Status', no_wrap=True)
    processes = {process.artifact_id: process for process in snapshot.processes}
    for link in correlate_network(snapshot):
        owner = str(processes[link.process_id].pid) if link.process_id is not None else 'unresolved'
        table.add_row(str(link.connection_id), owner, link.status)
    console.print(table)

    console.print('\nService command targets', style='bold')
    for service in sorted(snapshot.services, key=lambda item: item.artifact_id.int):
        if service.command is None:
            console.print(literal(f'{service.name}: command unavailable'))
            continue
        target = parse_command_target(service.command)
        console.print(literal(f'{service.name}: {target.path or "unresolved"} — {target.reason}'))

    console.print('\nFactual timeline (UTC)', style='bold')
    for event in build_timeline(snapshot):
        timestamp = event.timestamp.isoformat().replace('+00:00', 'Z')
        console.print(literal(f'{timestamp}  {event.kind}  ({event.basis})'))
        console.print(literal(f'  {event.description}'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
