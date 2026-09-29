"""Run, Startup, service and task persistence projections."""
import subprocess
from pydantic import ValidationError

from irsnapshot.collectors.base import CollectionContext, RunBuilder, classify_exception
from irsnapshot.collectors.contracts import (RunResponse, ShortcutInputs,
    ShortcutsResponse, StartupResponse, WindowsQuery)
from irsnapshot.models import CollectorName, PersistenceArtifact, ServiceArtifact, ScheduledTaskArtifact


def _add(run: RunBuilder[PersistenceArtifact], data: dict, target: str) -> None:
    try:
        run.items.append(PersistenceArtifact(artifact_id=run.context.id_factory(),
                                             observed_at=run.context.clock(), **data))
    except ValidationError as exc:
        run.issue('invalid_data', 'persistence record invalid', target=target,
                  exception_type=type(exc).__name__)


def _projected_command(executable: str | None, arguments: str | None) -> str | None:
    if executable is None:
        return None
    return subprocess.list2cmdline([executable]) + ((' ' + arguments) if arguments else '')


def collect(context: CollectionContext, services: list[ServiceArtifact],
            tasks: list[ScheduledTaskArtifact]):
    run = RunBuilder[PersistenceArtifact](context, CollectorName.PERSISTENCE,
        ['HKCU/HKLM Run keys in 32/64-bit registry views',
         'current/common Startup folders and shortcut metadata; projected commands from structured shortcut fields',
         'collected services', 'every collected scheduled task action; projected commands from structured action fields'])
    try:
        response = context.windows.read_run_values(context.collector_sid)
        if not isinstance(response, RunResponse):
            raise TypeError('Run query returned the wrong response type')
        run.adapter_issues(response.issues)
        for record in response.items:
            _add(run, dict(kind='run_key', location=record.location,
                           entry_name=record.entry_name, command=record.command,
                           owner_sid=record.owner_sid, registry_view=record.registry_view,
                           registry_value_type=record.registry_value_type), record.location)
    except Exception as exc:
        run.issue(classify_exception(exc), 'Run key query unavailable',
                  exception_type=type(exc).__name__)

    startup_by_path: dict[str, PersistenceArtifact] = {}
    try:
        response = context.windows.startup_files(context.path_context)
        if not isinstance(response, StartupResponse):
            raise TypeError('Startup query returned the wrong response type')
        run.adapter_issues(response.issues)
        for record in response.items:
            _add(run, dict(kind='startup_folder', location=record.path,
                           entry_name=record.path.replace('/', '\\').rsplit('\\', 1)[-1],
                           owner_sid=record.owner_sid), record.path)
            if run.items and run.items[-1].kind == 'startup_folder' and run.items[-1].location == record.path:
                startup_by_path[record.path.casefold()] = run.items[-1]
    except Exception as exc:
        run.issue(classify_exception(exc), 'Startup folder query unavailable',
                  exception_type=type(exc).__name__)

    shortcut_paths = [item.location for item in startup_by_path.values()
                      if item.location.casefold().endswith('.lnk')]
    if shortcut_paths:
        try:
            response = context.windows.run_query(WindowsQuery.SHORTCUTS,
                ShortcutInputs(paths=shortcut_paths))
            if not isinstance(response, ShortcutsResponse):
                raise TypeError('shortcut query returned the wrong response type')
            for issue in response.issues:
                artifact = startup_by_path.get((issue.target or '').casefold())
                run.adapter_issues([issue], artifact_id=artifact.artifact_id if artifact else None)
            returned_paths: set[str] = set()
            for record in response.items:
                returned_paths.add(record.path.casefold())
                artifact = startup_by_path.get(record.path.casefold())
                if artifact is None:
                    run.issue('invalid_data', 'shortcut response has no matching Startup file',
                              target=record.path)
                    continue
                artifact.target_path = record.target_path
                if record.target_path is not None:
                    artifact.command = _projected_command(record.target_path, record.arguments)
                else:
                    run.issue('unavailable', 'shortcut target unresolved',
                              artifact_id=artifact.artifact_id, target=record.path,
                              field='target_path')
            for path in shortcut_paths:
                if path.casefold() not in returned_paths and not any(
                    issue.target is not None and issue.target.casefold() == path.casefold()
                    for issue in response.issues):
                    artifact = startup_by_path[path.casefold()]
                    run.issue('unavailable', 'shortcut metadata absent from response',
                              artifact_id=artifact.artifact_id, target=path,
                              field='target_path')
        except Exception as exc:
            run.issue(classify_exception(exc), 'shortcut metadata query unavailable',
                      exception_type=type(exc).__name__)

    for service in services:
        _add(run, dict(kind='service', location=service.name, entry_name=service.name,
                       command=service.command, source_artifact_id=service.artifact_id), service.name)
    for task in tasks:
        for index, action in enumerate(task.actions):
            _add(run, dict(kind='scheduled_task', location=task.task_path,
                           entry_name=task.name,
                           command=_projected_command(action.executable, action.arguments),
                           target_path=action.executable, enabled=task.enabled,
                           source_artifact_id=task.artifact_id, action_index=index), task.task_path)
    return run.finish()
