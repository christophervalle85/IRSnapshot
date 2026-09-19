"""Current PID associations, without claiming historical network ownership."""
from irsnapshot.models import NetworkProcessLink, SystemSnapshot


def correlate_network(snapshot: SystemSnapshot) -> list[NetworkProcessLink]:
    snapshot = SystemSnapshot.model_validate(snapshot)
    processes = {process.pid: process for process in snapshot.processes}
    result: list[NetworkProcessLink] = []
    for connection in sorted(snapshot.network, key=lambda c: c.artifact_id.int):
        process = processes.get(connection.owning_pid) if connection.owning_pid is not None else None
        if connection.owning_pid is None:
            status = 'owner_unavailable'
        elif process is None:
            status = 'process_missing'
        elif process.created_at is not None and process.created_at > connection.observed_at:
            status = 'temporal_conflict'
        else:
            status = 'pid_match'
        result.append(NetworkProcessLink(
            connection_id=connection.artifact_id, status=status,
            process_id=process.artifact_id if status == 'pid_match' and process is not None else None,
        ))
    return result
