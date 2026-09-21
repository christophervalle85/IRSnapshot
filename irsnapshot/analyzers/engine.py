"""Reproducible analysis of captured evidence, with per-rule fault isolation."""
from collections.abc import Sequence
from copy import deepcopy
import json

from irsnapshot.analyzers.network import correlate_network
from irsnapshot.analyzers.process_tree import build_process_tree
from irsnapshot.correlation.relationships import correlate_findings
from irsnapshot.correlation.timeline import build_timeline
from irsnapshot.models import AnalysisIssue, AnalysisResult, Finding, InvestigationReport, SystemSnapshot
from irsnapshot.rules import DEFAULT_RULES
from irsnapshot.rules.base import AnalysisContext, Rule, finding_id
from irsnapshot.severity import Severity

RULESET_VERSION = '1.0.0'


class AnalysisError(RuntimeError):
    """A structural analysis component failed; no report can be claimed complete."""


def analyze_snapshot(snapshot: SystemSnapshot, rules: Sequence[Rule] = DEFAULT_RULES) -> AnalysisResult:
    """Analyze a revalidated copy; collection coverage is independent of success.

    Each evaluator receives a private deep copy. Exceptions and malformed findings
    discard that rule's batch only. Structural failures are fatal AnalysisError.
    KeyboardInterrupt and SystemExit always propagate.
    """
    snapshot = SystemSnapshot.model_validate(snapshot).model_copy(deep=True)
    rules = tuple(rules)
    identifiers = [getattr(rule, 'rule_id', None) for rule in rules]
    if any(identifiers.count(ident) > 1 for ident in identifiers if isinstance(ident, str)):
        raise ValueError('Duplicate rule IDs are invalid configuration')
    component = 'process tree'
    try:
        tree = build_process_tree(snapshot.processes)
        component = 'network correlation'
        links = correlate_network(snapshot)
        component = 'timeline'
        timeline = build_timeline(snapshot)
    except Exception as exc:
        raise AnalysisError(f'{component} failed ({type(exc).__name__})') from exc
    context = AnalysisContext(snapshot=snapshot, tree=tree, network_links=links)
    findings: list[Finding] = []
    issues: list[AnalysisIssue] = []
    for rule in rules:
        rule_id = getattr(rule, 'rule_id', None)
        try:
            _validate_rule(rule)
            returned = rule.evaluate(deepcopy(context))
            if not isinstance(returned, list):
                raise ValueError('Rule must return a list of Finding models')
            # Validate against pristine evidence, not the evaluator's private copy.
            batch = [_validate_finding(value, rule, snapshot) for value in returned]
            findings.extend(batch)
        except Exception as exc:
            issues.append(AnalysisIssue(
                component='rule', rule_id=rule_id if isinstance(rule_id, str) else None,
                message=f'Rule evaluation failed ({type(exc).__name__}); results for this rule are unavailable.',
            ))
    findings = _deduplicate(findings)
    issues.sort(key=lambda issue: (issue.rule_id or '', issue.component, issue.message))
    try:
        component = 'finding correlation'
        contexts = correlate_findings(findings, tree, links)
        component = 'report validation'
        analysis = AnalysisResult(
            snapshot_id=snapshot.snapshot_id, ruleset_version=RULESET_VERSION,
            complete=not issues, findings=findings, process_tree=tree, network_links=links,
            finding_context=contexts, timeline=timeline, issues=issues,
        )
        return InvestigationReport(snapshot=snapshot, analysis=analysis).analysis
    except Exception as exc:
        raise AnalysisError(f'{component} failed ({type(exc).__name__})') from exc


def _validate_rule(rule: Rule) -> None:
    if (not isinstance(rule, Rule) or not isinstance(rule.rule_id, str) or not rule.rule_id
            or not isinstance(rule.title, str) or not rule.title
            or not isinstance(rule.severity, Severity) or not callable(rule.evaluator)
            or (rule.mitre_technique is not None and not isinstance(rule.mitre_technique, str))):
        raise ValueError('Invalid rule metadata')


def _validate_finding(value: Finding, rule: Rule, snapshot: SystemSnapshot) -> Finding:
    if not isinstance(value, Finding):
        raise ValueError('Rule must return Finding models')
    result = Finding.model_validate(value).model_copy(deep=True)
    if (result.rule_id, result.title, result.severity, result.mitre_technique) != (
            rule.rule_id, rule.title, rule.severity, rule.mitre_technique):
        raise ValueError('Finding metadata must match its rule')
    allowed = {artifact.artifact_id for artifact in snapshot.artifacts()}
    if not set(result.artifact_ids).issubset(allowed):
        raise ValueError('Finding references unknown artifacts')
    allowed_pids = {p.pid for p in snapshot.processes if p.artifact_id in result.artifact_ids}
    if not set(result.pids).issubset(allowed_pids):
        raise ValueError('PID hints must match referenced process artifacts')
    result.artifact_ids.sort(key=lambda ident: ident.int)
    result.pids = sorted(set(result.pids))
    result.finding_id = finding_id(snapshot.snapshot_id, rule.rule_id, result.artifact_ids)
    return result


def _evidence_key(item) -> str:
    return json.dumps(item.model_dump(mode='json'), sort_keys=True, ensure_ascii=True, separators=(',', ':'))


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple, list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.rule_id, tuple(finding.artifact_ids)), []).append(finding)
    output: list[Finding] = []
    for group in groups.values():
        result = group[0].model_copy(deep=True)
        evidence = {_evidence_key(item): item for finding in group for item in finding.evidence}
        result.evidence = [evidence[key] for key in sorted(evidence)]
        result.pids = sorted({pid for finding in group for pid in finding.pids})
        result.description = '\n'.join(sorted({finding.description for finding in group}))
        output.append(result)
    return sorted(output, key=lambda finding: (-finding.severity.rank, finding.rule_id, finding.finding_id.int))
