"""Windows service inventory with independent field reads."""
from pydantic import ValidationError
from irsnapshot.collectors.base import CollectionContext, RunBuilder, classify_exception
from irsnapshot.models import CollectorName, ServiceArtifact

_FIELDS = {'display_name': 'display_name', 'status': 'status', 'binpath': 'command',
           'start_type': 'startup_type', 'username': 'username', 'pid': 'pid'}


def collect(context: CollectionContext):
    run = RunBuilder[ServiceArtifact](context, CollectorName.SERVICES, ['Windows service manager via psutil'])
    try:
        iterator = iter(context.windows.service_iter())
    except Exception as exc:
        run.issue(classify_exception(exc), 'service enumeration unavailable',
                  exception_type=type(exc).__name__)
        return run.finish()
    while True:
        try:
            service = next(iterator)
        except StopIteration:
            break
        except Exception as exc:
            run.issue(classify_exception(exc), 'service enumeration interrupted',
                      exception_type=type(exc).__name__)
            break
        observed_at = context.clock()
        try:
            name = service.name()
            if not name:
                raise ValueError('service name empty')
        except Exception as exc:
            run.issue(classify_exception(exc) if not isinstance(exc, ValueError) else 'invalid_data',
                      'service name unavailable', exception_type=type(exc).__name__)
            continue
        artifact_id = context.id_factory()
        data = dict(artifact_id=artifact_id, observed_at=observed_at, name=name)
        for method, field in _FIELDS.items():
            try:
                value = getattr(service, method)()
                if field == 'pid' and value is not None and (type(value) is not int or value < 0):
                    raise ValueError('service PID invalid')
                if field != 'pid' and value is not None and type(value) is not str:
                    raise ValueError(f'service {field} invalid')
                data[field] = value
            except Exception as exc:
                run.issue('invalid_data' if isinstance(exc, ValueError) else classify_exception(exc),
                          f'service {field} unavailable or invalid',
                          artifact_id=artifact_id, target=name, field=field,
                          exception_type=type(exc).__name__)
        try:
            run.items.append(ServiceArtifact(**data))
        except ValidationError as exc:
            run.issues = [i for i in run.issues if i.artifact_id != artifact_id]
            run.issue('invalid_data', 'service record invalid', target=name,
                      exception_type=type(exc).__name__)
    return run.finish()
