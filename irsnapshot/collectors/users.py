"""Current principal, account and logged-in session inventory."""
from pydantic import ValidationError
from irsnapshot.collectors.base import CollectionContext, RunBuilder, classify_exception, reported_time
from irsnapshot.collectors.contracts import UsersResponse, WindowsQuery
from irsnapshot.models import CollectorName, UserArtifact


def collect(context: CollectionContext):
    run = RunBuilder[UserArtifact](context, CollectorName.USERS,
        ['current token', 'local accounts', 'direct Administrators members', 'psutil sessions'])
    try:
        response = context.windows.run_query(WindowsQuery.USERS)
        if not isinstance(response, UsersResponse):
            raise TypeError('user query returned the wrong response type')
        run.adapter_issues(response.issues)
        for record in response.items:
            observed_at = context.clock()
            artifact_id = context.id_factory()
            data = record.model_dump()
            if data['logged_in_at'] is not None:
                try:
                    data['logged_in_at'] = reported_time(data['logged_in_at'], observed_at)
                except (ValueError, OverflowError, OSError) as exc:
                    data['logged_in_at'] = None
                    run.issue('invalid_data', 'user logon time invalid', artifact_id=artifact_id,
                              field='logged_in_at', exception_type=type(exc).__name__)
            try:
                run.items.append(UserArtifact(artifact_id=artifact_id, observed_at=observed_at, **data))
            except ValidationError as exc:
                run.issues = [i for i in run.issues if i.artifact_id != artifact_id]
                run.issue('invalid_data', 'user record invalid', exception_type=type(exc).__name__)
    except Exception as exc:
        run.issue('parse_error' if isinstance(exc, TypeError) else classify_exception(exc),
                  'account query unavailable or invalid',
                  exception_type=type(exc).__name__)
    try:
        sessions = context.windows.sessions()
        for session in sessions:
            observed_at = context.clock()
            artifact_id = context.id_factory()
            data = dict(name=session.name, source='logged_in_session',
                        session_name=getattr(session, 'terminal', None))
            try:
                started = getattr(session, 'started', None)
                if started is not None:
                    data['logged_in_at'] = reported_time(started, observed_at)
            except (ValueError, OverflowError, OSError) as exc:
                run.issue('invalid_data', 'session logon time invalid', artifact_id=artifact_id,
                          field='logged_in_at', exception_type=type(exc).__name__)
            try:
                run.items.append(UserArtifact(artifact_id=artifact_id, observed_at=observed_at, **data))
            except ValidationError as exc:
                run.issues = [i for i in run.issues if i.artifact_id != artifact_id]
                run.issue('invalid_data', 'session record invalid', exception_type=type(exc).__name__)
    except Exception as exc:
        run.issue(classify_exception(exc), 'session query unavailable',
                  exception_type=type(exc).__name__)
    return run.finish()
