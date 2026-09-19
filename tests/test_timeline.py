"""Collection observations never substitute for unknown forensic event times."""
from datetime import UTC, datetime
from uuid import UUID


def test_timeline_uses_reported_times_and_labelled_observation_bounds(snapshot_data):
    from irsnapshot.correlation.timeline import build_timeline
    from irsnapshot.models import SystemSnapshot
    snapshot_data['users'][0].update(source='logged_in_session',logged_in_at='2026-09-17T13:00:00Z')
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    events = build_timeline(snapshot)
    assert [e.kind for e in events] == ['boot','user_logon','process_start','collection_start','collection_end']
    assert [e.basis for e in events] == ['reported']*3 + ['observed']*2
    assert events[2].timestamp == datetime(2026,9,17,14,tzinfo=UTC)
    assert events[2].artifact_ids == [UUID(int=2)]


def test_unknown_process_time_does_not_become_observation_time(snapshot_data):
    from irsnapshot.correlation.timeline import build_timeline
    from irsnapshot.models import SystemSnapshot
    snapshot_data['processes'][0]['created_at'] = None
    events = build_timeline(SystemSnapshot.model_validate(snapshot_data))
    assert 'process_start' not in [e.kind for e in events]
    assert [e.kind for e in events] == ['boot','collection_start','collection_end']


def test_task_schedule_is_not_task_execution_and_timeline_is_deterministic(snapshot_data):
    from irsnapshot.correlation.timeline import build_timeline
    from irsnapshot.models import SystemSnapshot
    snapshot_data['scheduled_tasks'][0]['triggers'][0]['start_at'] = '2026-09-18T12:00:00Z'
    snapshot = SystemSnapshot.model_validate(snapshot_data)
    original = snapshot.model_dump_json()
    assert build_timeline(snapshot) == build_timeline(snapshot)
    assert all(e.timestamp <= snapshot.finished_at for e in build_timeline(snapshot))
    assert snapshot.model_dump_json() == original
