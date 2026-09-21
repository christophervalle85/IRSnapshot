"""Deterministic persistence rules over captured snapshot evidence."""

from collections.abc import Iterable
from uuid import UUID

from irsnapshot.analyzers.paths import PathAssessment, classify_path
from irsnapshot.analyzers.persistence import (
    PersistenceTarget,
    parse_persistence_command,
    parse_task_action,
)
from irsnapshot.models import EvidenceItem
from irsnapshot.rules.base import AnalysisContext, Rule, make_finding
from irsnapshot.severity import Severity


def _evidence(
    artifact_id: UUID,
    field: str,
    value: str | int | bool | None,
    explanation: str,
) -> EvidenceItem:
    return EvidenceItem(
        artifact_id=artifact_id,
        field=field,
        value=value,
        explanation=explanation,
    )


def _path_evidence(
    artifact_id: UUID,
    *,
    path: str,
    provenance: str,
    assessment: PathAssessment,
    field_prefix: str = "",
) -> list[EvidenceItem]:
    return [
        _evidence(
            artifact_id,
            f"{field_prefix}target_provenance",
            provenance,
            "The parser records how the target was obtained without executing it.",
        ),
        _evidence(
            artifact_id,
            f"{field_prefix}target" if field_prefix else "interpreted_target",
            path,
            "The explicit executable or supported script target retained from evidence.",
        ),
        _evidence(
            artifact_id,
            f"{field_prefix}path_basis" if field_prefix else "path_basis",
            assessment.basis,
            (
                "Lexical comparison against captured endpoint roots; this is not an "
                "ACL, publisher, or trust conclusion."
            ),
        ),
    ]


def _matching_targets(
    context: AnalysisContext,
    target: PersistenceTarget,
    categories: Iterable[str],
    *,
    owner_sid: str | None = None,
    direct_provenance: str,
) -> list[tuple[str, str, PathAssessment]]:
    allowed = set(categories)
    candidates: list[tuple[str, str]] = []
    if target.executable and target.executable.casefold().endswith((".exe", ".com")):
        candidates.append((target.executable, direct_provenance))
    if target.path is not None and all(
        target.path.replace("/", "\\").casefold()
        != path.replace("/", "\\").casefold()
        for path, _ in candidates
    ):
        candidates.append((target.path, target.provenance))

    matches: list[tuple[str, str, PathAssessment]] = []
    for path, provenance in candidates:
        assessment = classify_path(path, context.snapshot.path_context, owner_sid)
        if assessment.category in allowed:
            matches.append((path, provenance, assessment))
    return matches


def _path_evidence_for_matches(
    artifact_id: UUID,
    matches: list[tuple[str, str, PathAssessment]],
    *,
    first_prefix: str = "",
) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    for match_index, (path, provenance, assessment) in enumerate(matches):
        if match_index == 0:
            prefix = first_prefix
        elif first_prefix:
            prefix = f"{first_prefix}targets[{match_index}]."
        else:
            prefix = f"interpreted_targets[{match_index}]."
        evidence.extend(
            _path_evidence(
                artifact_id,
                path=path,
                provenance=provenance,
                assessment=assessment,
                field_prefix=prefix,
            )
        )
    return evidence


def _evaluate_r001(context: AnalysisContext):
    findings = []
    for entry in context.snapshot.persistence:
        if entry.kind != "run_key" or entry.command is None:
            continue
        target = parse_persistence_command(entry.command)
        matches = _matching_targets(
            context,
            target,
            ("temp", "appdata", "profile"),
            owner_sid=entry.owner_sid,
            direct_provenance="raw_command_executable",
        )
        if not matches:
            continue
        evidence = [
            _evidence(
                entry.artifact_id,
                "entry_name",
                entry.entry_name,
                "Captured Run-key value name.",
            ),
            _evidence(
                entry.artifact_id,
                "location",
                entry.location,
                "Captured registry location and owner scope.",
            ),
            _evidence(
                entry.artifact_id,
                "command",
                entry.command,
                "Original Run-key command; it was not executed or rewritten.",
            ),
            *_path_evidence_for_matches(entry.artifact_id, matches),
        ]
        if entry.owner_sid is not None:
            evidence.append(
                _evidence(
                    entry.artifact_id,
                    "owner_sid",
                    entry.owner_sid,
                    "Captured owner SID used only for owner-scoped environment expansion.",
                )
            )
        findings.append(
            make_finding(
                context,
                R001,
                artifact_ids=[entry.artifact_id],
                evidence=evidence,
                description=(
                    "A Run-key command has an explicit executable or supported script "
                    "target in a conventional user-writable location identified from "
                    "captured roots. This is a lexical heuristic; legitimate logon "
                    "software can use the same locations."
                ),
            )
        )
    return findings


def _evaluate_r002(context: AnalysisContext):
    findings = []
    for task in context.snapshot.scheduled_tasks:
        matches: list[
            tuple[int, PersistenceTarget, list[tuple[str, str, PathAssessment]]]
        ] = []
        for index, action in enumerate(task.actions):
            target = parse_task_action(action)
            target_matches = _matching_targets(
                context,
                target,
                ("temp", "appdata"),
                direct_provenance="task_action_executable",
            )
            if target_matches:
                matches.append((index, target, target_matches))
        if not matches:
            continue

        evidence = [
            _evidence(task.artifact_id, "name", task.name, "Captured task name."),
            _evidence(
                task.artifact_id,
                "task_path",
                task.task_path,
                "Captured full task namespace path.",
            ),
            _evidence(
                task.artifact_id,
                "enabled",
                task.enabled,
                "Captured enabled state; disabled tasks remain inventory and findings.",
            ),
            _evidence(
                task.artifact_id,
                "state",
                task.state,
                "Captured task state; it is not evidence that the task ran.",
            ),
            _evidence(
                task.artifact_id,
                "principal",
                task.principal,
                "Captured task principal; no SID is inferred from this name.",
            ),
        ]
        for index, target, target_matches in matches:
            action = task.actions[index]
            prefix = f"actions[{index}]."
            evidence.extend(
                [
                    _evidence(
                        task.artifact_id,
                        f"{prefix}index",
                        index,
                        "Zero-based index of this matching action in captured order.",
                    ),
                    _evidence(
                        task.artifact_id,
                        f"{prefix}executable",
                        action.executable,
                        "Original separately collected task executable field.",
                    ),
                    _evidence(
                        task.artifact_id,
                        f"{prefix}arguments",
                        action.arguments,
                        "Original task argument string; it was not executed.",
                    ),
                    *_path_evidence_for_matches(
                        task.artifact_id, target_matches, first_prefix=prefix
                    ),
                ]
            )
        findings.append(
            make_finding(
                context,
                R002,
                artifact_ids=[task.artifact_id],
                evidence=evidence,
                description=(
                    "One or more scheduled-task actions have an explicit executable or "
                    "supported script target in conventional AppData or TEMP locations "
                    "identified from captured roots. This is a lexical heuristic; "
                    "legitimate per-user automation can use these locations."
                ),
            )
        )
    return findings


def _evaluate_r003(context: AnalysisContext):
    findings = []
    for service in context.snapshot.services:
        if service.command is None:
            continue
        target = parse_persistence_command(service.command)
        direct_matches = _matching_targets(
            context,
            PersistenceTarget(
                path=None,
                kind="unresolved",
                provenance="unresolved",
                raw_value=target.raw_value,
                executable=target.executable,
                arguments=target.arguments,
                reason=target.reason,
            ),
            ("temp", "appdata", "profile"),
            direct_provenance="raw_command_executable",
        )
        if not direct_matches:
            continue
        evidence = [
            _evidence(service.artifact_id, "name", service.name, "Captured service name."),
            _evidence(
                service.artifact_id,
                "status",
                service.status,
                "Captured service status; it is not installation-time evidence.",
            ),
            _evidence(
                service.artifact_id,
                "startup_type",
                service.startup_type,
                "Captured service startup type.",
            ),
            _evidence(
                service.artifact_id,
                "username",
                service.username,
                "Captured service account name; no SID or privilege is inferred.",
            ),
            _evidence(
                service.artifact_id,
                "command",
                service.command,
                "Original service command; it was not executed or rewritten.",
            ),
            *_path_evidence_for_matches(service.artifact_id, direct_matches),
        ]
        findings.append(
            make_finding(
                context,
                R003,
                artifact_ids=[service.artifact_id],
                evidence=evidence,
                description=(
                    "A service command's explicit executable is in a conventional "
                    "user-writable location identified from captured roots. This lexical "
                    "heuristic does not establish an exploitable ACL or malicious "
                    "service; development tools and per-user service software are "
                    "plausible benign explanations."
                ),
            )
        )
    return findings


R001 = Rule(
    rule_id="IRS-R001",
    title="Run-key target in a user-writable directory",
    severity=Severity.MEDIUM,
    evaluator=_evaluate_r001,
)
R002 = Rule(
    rule_id="IRS-R002",
    title="Scheduled-task target in AppData or TEMP",
    severity=Severity.MEDIUM,
    evaluator=_evaluate_r002,
)
R003 = Rule(
    rule_id="IRS-R003",
    title="Service executable in a user-writable directory",
    severity=Severity.HIGH,
    evaluator=_evaluate_r003,
)

PERSISTENCE_RULES = (R001, R002, R003)
