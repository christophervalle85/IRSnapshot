"""Process inventory with independent per-field reads."""
from pydantic import ValidationError

from irsnapshot.collectors.base import CollectionContext, RunBuilder, classify_exception, reported_time
from irsnapshot.models import CollectorName, ProcessArtifact


_FIELDS = {
    'ppid': 'ppid', 'name': 'name', 'exe': 'executable',
    'cmdline': 'command_line', 'username': 'username',
}


def collect(context: CollectionContext):
    run = RunBuilder[ProcessArtifact](context, CollectorName.PROCESSES, ['psutil process iterator'])
    seen: set[int] = set()
    try:
        iterator = iter(context.windows.process_iter())
    except Exception as exc:
        run.issue(classify_exception(exc), 'process enumeration unavailable',
                  exception_type=type(exc).__name__)
        return run.finish()
    while True:
        try:
            process = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            run.issue(classify_exception(exc), 'process enumeration interrupted',
                      exception_type=type(exc).__name__)
            break
        observed_at = context.clock()
        pid = process.pid
        if pid in seen:
            run.issue('invalid_data', 'duplicate PID in process inventory', target=str(pid), field='pid')
            continue
        seen.add(pid)
        artifact_id = context.id_factory()
        data = dict(artifact_id=artifact_id, observed_at=observed_at, pid=pid)
        for method, field in _FIELDS.items():
            try:
                value = getattr(process, method)()
                if field == 'ppid' and value is not None and (type(value) is not int or value < 0):
                    raise ValueError('parent PID invalid')
                if field == 'command_line' and value is not None and (
                    not isinstance(value, list) or any(type(arg) is not str for arg in value)):
                    raise ValueError('command line invalid')
                if field in ('name', 'executable', 'username') and value is not None and type(value) is not str:
                    raise ValueError(f'{field} invalid')
                data[field] = value
            except Exception as exc:
                run.issue('invalid_data' if isinstance(exc, ValueError) else classify_exception(exc),
                          f'process {field} unavailable or invalid',
                          artifact_id=artifact_id, target=str(pid), field=field,
                          exception_type=type(exc).__name__)
        try:
            raw_created_at = process.create_time()
        except Exception as exc:
            run.issue(classify_exception(exc), 'process creation time unavailable',
                      artifact_id=artifact_id, target=str(pid), field='created_at',
                      exception_type=type(exc).__name__)
        else:
            try:
                data['created_at'] = reported_time(raw_created_at, observed_at)
            except (ValueError, OverflowError, OSError) as exc:
                run.issue('invalid_data', 'process creation time invalid',
                          artifact_id=artifact_id, target=str(pid), field='created_at',
                          exception_type=type(exc).__name__)
        try:
            run.items.append(ProcessArtifact(**data))
        except ValidationError as exc:
            run.issues = [issue for issue in run.issues if issue.artifact_id != artifact_id]
            run.issue('invalid_data', 'process record invalid', target=str(pid),
                      exception_type=type(exc).__name__)
    return run.finish()
