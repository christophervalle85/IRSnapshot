"""Bounded, isolated collection of the seven snapshot evidence sources."""
from __future__ import annotations

import logging
import traceback
from datetime import datetime
from uuid import UUID

from irsnapshot import __version__
from irsnapshot.collectors import (network, persistence, processes,
                                   scheduled_tasks, services, system, users)
from irsnapshot.collectors.base import CollectionContext, SystemInventory
from irsnapshot.models import (CollectionIssue, CollectionStatus,
                               CollectorName, CollectorResult, CollectorRun,
                               NetworkConnection, PersistenceArtifact,
                               ProcessArtifact, ScheduledTaskArtifact,
                               ServiceArtifact, SystemSnapshot,
                               UserArtifact)

logger = logging.getLogger(__name__)

_RESULT_TYPES = {
    CollectorName.SYSTEM: SystemInventory,
    CollectorName.PROCESSES: ProcessArtifact,
    CollectorName.NETWORK: NetworkConnection,
    CollectorName.USERS: UserArtifact,
    CollectorName.SERVICES: ServiceArtifact,
    CollectorName.SCHEDULED_TASKS: ScheduledTaskArtifact,
    CollectorName.PERSISTENCE: PersistenceArtifact,
}
_SYSTEM_FIELDS = (
    "hostname", "windows_version", "architecture", "current_time", "boot_time",
    "collector_username", "collector_sid", "elevated",
)


def _validated_result(name: CollectorName, raw: object, snapshot_started: datetime,
                      source_finished: datetime,
                      known_ids: set[UUID]) -> CollectorResult:
    result = CollectorResult[_RESULT_TYPES[name]].model_validate(raw)
    run = result.run
    if (run.collector != name or run.started_at < snapshot_started
            or run.finished_at > source_finished):
        raise ValueError("collector name or interval is inconsistent")
    if name == CollectorName.SYSTEM:
        if len(result.items) > 1 or (run.status in (CollectionStatus.OK, CollectionStatus.PARTIAL)
                                     and len(result.items) != 1):
            raise ValueError("system source must yield one item when available")
        artifacts = [item.system for item in result.items]
        if artifacts:
            system_artifact = artifacts[0]
            issue_fields = {issue.field for issue in run.issues
                            if issue.artifact_id == system_artifact.artifact_id}
            if any(getattr(system_artifact, field) is None and field not in issue_fields
                   for field in _SYSTEM_FIELDS):
                raise ValueError("system source omitted unavailable-field issues")
    else:
        artifacts = result.items
    item_ids = [item.artifact_id for item in artifacts]
    if len(set(item_ids)) != len(item_ids) or known_ids.intersection(item_ids):
        raise ValueError("collector returned duplicate artifact IDs")
    if name == CollectorName.PROCESSES:
        pids = [item.pid for item in artifacts]
        if len(set(pids)) != len(pids):
            raise ValueError("collector returned duplicate PIDs")
    item_index = set(item_ids)
    if any(not run.started_at <= item.observed_at <= run.finished_at for item in artifacts):
        raise ValueError("artifact lies outside its collector interval")
    if any(issue.artifact_id is not None and issue.artifact_id not in item_index
           for issue in run.issues):
        raise ValueError("issue references an absent artifact")
    return result


def _validate_persistence_sources(result: CollectorResult,
                                  results: dict[CollectorName, CollectorResult]) -> None:
    service_ids = {item.artifact_id for item in results[CollectorName.SERVICES].items}
    tasks = {item.artifact_id: item for item in results[CollectorName.SCHEDULED_TASKS].items}
    for item in result.items:
        if item.kind == "service" and item.source_artifact_id not in service_ids:
            raise ValueError("service persistence source is absent")
        if item.kind == "scheduled_task":
            task = tasks.get(item.source_artifact_id)
            if task is None or item.action_index >= len(task.actions):
                raise ValueError("scheduled-task persistence source or action is absent")


def _failed_result(context: CollectionContext, name: CollectorName,
                   started_at: datetime, exc: Exception) -> CollectorResult:
    finished_at = context.clock()
    # External exception text may contain captured commands or account data.
    issue = CollectionIssue(
        collector=name, category="invalid_data" if isinstance(exc, ValueError) else "unexpected_error",
        message="Collector result was invalid." if isinstance(exc, ValueError)
                else "Collector failed unexpectedly.",
        observed_at=finished_at, exception_type=type(exc).__name__,
    )
    return CollectorResult(items=[], run=CollectorRun(
        collector=name, status=CollectionStatus.FAILED,
        started_at=started_at, finished_at=finished_at, item_count=0,
        scope=[f"{name.value} source unavailable"], issues=[issue],
    ))


def collect_snapshot(context: CollectionContext | None = None) -> SystemSnapshot:
    """Collect local Windows evidence and retain coverage for failed sources."""
    context = context if context is not None else CollectionContext()
    context.windows.ensure_supported()
    started_at = context.clock()
    results: dict[CollectorName, CollectorResult] = {}
    known_ids: set[UUID] = set()
    modules = {
        CollectorName.SYSTEM: system,
        CollectorName.PROCESSES: processes,
        CollectorName.NETWORK: network,
        CollectorName.USERS: users,
        CollectorName.SERVICES: services,
        CollectorName.SCHEDULED_TASKS: scheduled_tasks,
        CollectorName.PERSISTENCE: persistence,
    }
    for name in CollectorName:
        source_started = context.clock()
        original_snapshot_id = context.snapshot_id
        original_clock = context.clock
        original_id_factory = context.id_factory
        original_windows = context.windows
        original_paths = context.path_context.model_copy(deep=True)
        original_sid = context.collector_sid
        try:
            if name == CollectorName.PERSISTENCE:
                raw = modules[name].collect(
                    context,
                    [item.model_copy(deep=True) for item in results[CollectorName.SERVICES].items],
                    [item.model_copy(deep=True) for item in results[CollectorName.SCHEDULED_TASKS].items],
                )
            else:
                raw = modules[name].collect(context)
            context.snapshot_id = original_snapshot_id
            context.clock = original_clock
            context.id_factory = original_id_factory
            context.windows = original_windows
            source_finished = context.clock()
            result = _validated_result(name, raw, started_at, source_finished, known_ids)
            if name == CollectorName.PERSISTENCE:
                _validate_persistence_sources(result, results)
            if name == CollectorName.PERSISTENCE and result.run.status in (
                    CollectionStatus.OK, CollectionStatus.PARTIAL):
                missing = [upstream.value for upstream in (
                    CollectorName.SERVICES, CollectorName.SCHEDULED_TASKS)
                    if results[upstream].run.status != CollectionStatus.OK]
                if missing:
                    result.run.issues.append(CollectionIssue(
                        collector=name, category="unavailable",
                        message=f"Derived coverage limited by incomplete {', '.join(missing)} collection.",
                        observed_at=result.run.finished_at,
                    ))
                    result.run.status = CollectionStatus.PARTIAL
                    result = _validated_result(name, result, started_at, source_finished, known_ids)
            known_ids.update(item.system.artifact_id if name == CollectorName.SYSTEM
                             else item.artifact_id for item in result.items)
            if name == CollectorName.SYSTEM and result.items:
                context.path_context = result.items[0].path_context.model_copy(deep=True)
                context.collector_sid = result.items[0].system.collector_sid
            else:
                context.path_context = original_paths
                context.collector_sid = original_sid
        except Exception as exc:
            formatted = ''.join(traceback.format_exception(exc, chain=True))
            safe_traceback = ''.join(
                char if char == '\n' or char.isprintable()
                else char.encode('unicode_escape').decode('ascii')
                for char in formatted
            )
            logger.error("%s collection failed\n%s", name.value, safe_traceback.rstrip('\n'))
            context.snapshot_id = original_snapshot_id
            context.clock = original_clock
            context.id_factory = original_id_factory
            context.windows = original_windows
            result = _failed_result(context, name, source_started, exc)
            context.path_context = original_paths
            context.collector_sid = original_sid
        results[name] = result
    snapshot = SystemSnapshot(
        snapshot_id=context.snapshot_id, tool_version=__version__,
        started_at=started_at, finished_at=context.clock(),
        system=(results[CollectorName.SYSTEM].items[0].system
                if results[CollectorName.SYSTEM].items else None),
        processes=results[CollectorName.PROCESSES].items,
        network=results[CollectorName.NETWORK].items,
        users=results[CollectorName.USERS].items,
        services=results[CollectorName.SERVICES].items,
        scheduled_tasks=results[CollectorName.SCHEDULED_TASKS].items,
        persistence=results[CollectorName.PERSISTENCE].items,
        path_context=context.path_context.model_copy(deep=True),
        collector_runs=[results[name].run for name in CollectorName],
    )
    return SystemSnapshot.model_validate(snapshot)
