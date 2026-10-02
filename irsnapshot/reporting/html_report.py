"""Deterministic, escaped, standalone analyst reports; no endpoint access."""
from datetime import UTC, datetime
from importlib.resources import files
import json
from pathlib import Path

from jinja2 import Environment, StrictUndefined

from irsnapshot.models import CollectionStatus, InvestigationReport
from irsnapshot.reporting.json_report import MAX_REPORT_BYTES
from irsnapshot.severity import Severity
from irsnapshot.storage import _publish_bytes


def _utc(value: datetime | None) -> str:
    return value.astimezone(UTC).isoformat().replace('+00:00', 'Z') + ' (UTC)' if value else 'unavailable'


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def render_html(report: InvestigationReport) -> str:
    """Revalidate mutable evidence and render only supplied analysis relationships."""
    report = InvestigationReport.model_validate(report)
    snapshot, analysis = report.snapshot, report.analysis
    processes = {p.artifact_id: p for p in snapshot.processes}
    nodes = {n.process_id: n for n in analysis.process_tree.nodes}
    tree_rows = []
    pending = [(ident, 0) for ident in reversed(analysis.process_tree.root_ids)]
    while pending:
        ident, depth = pending.pop()
        node = nodes[ident]
        tree_rows.append((processes[ident], node, depth))
        pending.extend((child, depth + 1) for child in reversed(node.child_ids))
    # Flat rows avoid both Python/Jinja recursion and deeply nested browser DOM.
    missing_tree = [p for p in snapshot.processes if p.artifact_id not in nodes]
    contexts = {c.finding_id: c for c in analysis.finding_context}
    findings = sorted(analysis.findings, key=lambda f: (-f.severity.rank, f.rule_id, f.finding_id.int))
    referenced = {ident for f in findings for ident in f.artifact_ids if ident in processes}
    referenced.update(ident for c in analysis.finding_context
                      for ident in c.process_ids + c.ancestor_ids + c.child_ids)
    links = {link.connection_id: link for link in analysis.network_links}
    persistence_ids = {p.artifact_id for p in snapshot.persistence + snapshot.services + snapshot.scheduled_tasks}
    raw_groups = [('system', [snapshot.system] if snapshot.system else []),
                  *[(name, getattr(snapshot, name)) for name in
                    ('processes', 'network', 'users', 'services', 'scheduled_tasks', 'persistence')]]
    environment = Environment(autoescape=True, undefined=StrictUndefined, keep_trailing_newline=True)
    environment.filters.update(utc=_utc, evidence_json=_json)
    template = environment.from_string(files('irsnapshot.reporting').joinpath('templates/report.html.j2').read_text(encoding='utf-8'))
    rendered = template.render(
        report=report, snapshot=snapshot, analysis=analysis, findings=findings,
        partial=not analysis.complete or any(r.status != CollectionStatus.OK for r in snapshot.collector_runs),
        counts=[(severity.value, sum(f.severity == severity for f in findings)) for severity in reversed(Severity)],
        processes=processes, contexts=contexts, tree_rows=tree_rows, missing_tree=missing_tree,
        referenced=[p for p in sorted(snapshot.processes, key=lambda p: (p.pid, p.artifact_id.int)) if p.artifact_id in referenced],
        links=links, persistence_findings=[f for f in findings if persistence_ids.intersection(f.artifact_ids)],
        raw_groups=raw_groups, coverage={run.collector.value: run for run in snapshot.collector_runs},
    )
    if len(rendered.encode('utf-8')) > MAX_REPORT_BYTES:
        raise ValueError('Report exceeds the supported file size limit (128 MiB)')
    return rendered


def write_html_report(report: InvestigationReport, output: Path, *, overwrite: bool = False) -> None:
    """Publish bounded UTF-8 HTML atomically, with explicit overwrite only."""
    _publish_bytes(render_html(report).encode('utf-8'), Path(output), overwrite=overwrite)
