"""Scheduled task definitions, including every action and raw trigger boundary."""
from pydantic import ValidationError
from irsnapshot.collectors.base import CollectionContext, RunBuilder
from irsnapshot.collectors.contracts import TasksResponse, WindowsQuery
from irsnapshot.models import CollectorName, ScheduledTaskArtifact


def collect(context: CollectionContext):
    run = RunBuilder[ScheduledTaskArtifact](context, CollectorName.SCHEDULED_TASKS,
        ['local scheduled task definitions and actions'])
    response = context.windows.run_query(WindowsQuery.TASKS)
    if not isinstance(response, TasksResponse):
        run.issue('parse_error', 'task query returned the wrong response type')
        return run.finish()
    run.adapter_issues(response.issues)
    for record in response.items:
        observed_at = context.clock()
        try:
            run.items.append(ScheduledTaskArtifact(artifact_id=context.id_factory(),
                                                   observed_at=observed_at, **record.model_dump()))
        except ValidationError as exc:
            run.issue('invalid_data', 'scheduled task record invalid',
                      target=record.task_path, exception_type=type(exc).__name__)
    return run.finish()
