"""System facts and captured path context."""
from irsnapshot.collectors.base import CollectionContext, RunBuilder, SystemInventory, reported_time
from irsnapshot.models import CollectorName, SystemInfo

_FIELDS = ('hostname', 'windows_version', 'architecture', 'boot_time',
           'collector_username', 'collector_sid', 'elevated')


def collect(context: CollectionContext):
    run = RunBuilder[SystemInventory](context, CollectorName.SYSTEM,
                                      ['local system facts', 'current security token', 'known paths'])
    reading = context.windows.system_reading()
    observed_at = context.clock()
    artifact_id = context.id_factory()
    data = {field: getattr(reading, field) for field in _FIELDS}
    data.update(artifact_id=artifact_id, observed_at=observed_at, current_time=observed_at)
    if data['boot_time'] is not None:
        try:
            data['boot_time'] = reported_time(data['boot_time'], observed_at)
        except (ValueError, OverflowError, OSError) as exc:
            data['boot_time'] = None
            run.issue('invalid_data', 'boot time invalid or later than observation',
                      artifact_id=artifact_id, field='boot_time', exception_type=type(exc).__name__)
    run.adapter_issues(reading.issues, artifact_id=artifact_id)
    for field in (*_FIELDS, 'current_time'):
        if data[field] is None and not any(i.field == field and i.artifact_id == artifact_id for i in run.issues):
            run.issue('unavailable', f'system {field} unavailable', artifact_id=artifact_id, field=field)
    system = SystemInfo(**data)
    run.items.append(SystemInventory(system=system, path_context=reading.path_context))
    context.path_context = reading.path_context
    context.collector_sid = reading.collector_sid
    return run.finish()
