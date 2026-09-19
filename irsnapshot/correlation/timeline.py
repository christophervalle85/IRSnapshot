"""Known event timestamps, separate from observations and planned schedules."""
from irsnapshot.models import SystemSnapshot, TimelineEvent


def build_timeline(snapshot: SystemSnapshot) -> list[TimelineEvent]:
    snapshot = SystemSnapshot.model_validate(snapshot)
    events = [
        TimelineEvent(timestamp=snapshot.started_at, kind='collection_start', basis='observed', description='Collection started'),
        TimelineEvent(timestamp=snapshot.finished_at, kind='collection_end', basis='observed', description='Collection finished'),
    ]
    if snapshot.system is not None and snapshot.system.boot_time is not None:
        events.append(TimelineEvent(timestamp=snapshot.system.boot_time, kind='boot', basis='reported',
                                    description='System boot time', artifact_ids=[snapshot.system.artifact_id]))
    for process in snapshot.processes:
        if process.created_at is not None:
            events.append(TimelineEvent(timestamp=process.created_at, kind='process_start', basis='reported',
                                        description=f'Process started: {process.name or "unknown"} (PID {process.pid})',
                                        artifact_ids=[process.artifact_id]))
    for user in snapshot.users:
        if user.source == 'logged_in_session' and user.logged_in_at is not None:
            events.append(TimelineEvent(timestamp=user.logged_in_at, kind='user_logon', basis='reported',
                                        description=f'User session logon: {user.name}', artifact_ids=[user.artifact_id]))
    return sorted(events, key=lambda e: (e.timestamp, e.kind, tuple(i.int for i in e.artifact_ids), e.description))
