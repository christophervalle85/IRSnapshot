"""Shared contracts for pure, deterministic offline rules."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import UUID, uuid5

from irsnapshot.models import (
    EvidenceItem,
    Finding,
    NetworkProcessLink,
    ProcessTree,
    SystemSnapshot,
)
from irsnapshot.severity import Severity


@dataclass(frozen=True)
class AnalysisContext:
    """Validated snapshot evidence plus precomputed structural relationships."""

    snapshot: SystemSnapshot
    tree: ProcessTree
    network_links: list[NetworkProcessLink]


@dataclass(frozen=True)
class Rule:
    """Immutable rule metadata paired with a pure evaluator."""

    rule_id: str
    title: str
    severity: Severity
    evaluator: Callable[[AnalysisContext], list[Finding]]
    mitre_technique: str | None = None

    def evaluate(self, context: AnalysisContext) -> list[Finding]:
        return self.evaluator(context)


def finding_id(
    snapshot_id: UUID, rule_id: str, artifact_ids: Sequence[UUID]
) -> UUID:
    """Derive the stable finding identity from evidence identity only."""

    ordered = sorted(set(artifact_ids), key=lambda identifier: identifier.int)
    name = rule_id + "|" + ",".join(str(identifier) for identifier in ordered)
    return uuid5(snapshot_id, name)


def make_finding(
    context: AnalysisContext,
    rule: Rule,
    *,
    artifact_ids: Sequence[UUID],
    evidence: Sequence[EvidenceItem],
    description: str,
    pids: Sequence[int] = (),
) -> Finding:
    """Build a model-validated finding with canonical references and metadata."""

    ordered_artifacts = sorted(
        set(artifact_ids), key=lambda identifier: identifier.int
    )
    return Finding(
        finding_id=finding_id(
            context.snapshot.snapshot_id, rule.rule_id, ordered_artifacts
        ),
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        description=description,
        artifact_ids=ordered_artifacts,
        pids=sorted(set(pids)),
        evidence=list(evidence),
        mitre_technique=rule.mitre_technique,
    )
