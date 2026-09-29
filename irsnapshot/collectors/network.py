"""Internet socket table normalizer."""
import socket
from ipaddress import ip_address
from pydantic import ValidationError

from irsnapshot.collectors.base import CollectionContext, RunBuilder
from irsnapshot.models import CollectorName, NetworkConnection, NetworkEndpoint


def _endpoint(raw):
    if not raw:
        return None
    if hasattr(raw, 'ip'):
        return NetworkEndpoint(address=raw.ip, port=raw.port)
    return NetworkEndpoint(address=raw[0], port=raw[1])


def collect(context: CollectionContext):
    run = RunBuilder[NetworkConnection](context, CollectorName.NETWORK, ['psutil inet connections'])
    for raw in context.windows.net_connections():
        observed_at = context.clock()
        try:
            family = {socket.AF_INET: 'ipv4', socket.AF_INET6: 'ipv6'}[raw.family]
            protocol = {socket.SOCK_STREAM: 'tcp', socket.SOCK_DGRAM: 'udp'}[raw.type]
            local = _endpoint(raw.laddr)
            if local is None:
                raise ValueError('local endpoint missing')
            remote_invalid = False
            try:
                remote = _endpoint(raw.raddr)
                if remote is not None and ip_address(remote.address).version != (4 if family == 'ipv4' else 6):
                    raise ValueError('remote address family mismatch')
            except (AttributeError, IndexError, TypeError, ValueError, ValidationError):
                remote = None
                remote_invalid = True
            pid = raw.pid
            if pid is not None and (type(pid) is not int or pid < 0):
                pid = None
                owner_invalid = True
            else:
                owner_invalid = False
            item = NetworkConnection(artifact_id=context.id_factory(), observed_at=observed_at,
                                     family=family, protocol=protocol, local=local, remote=remote,
                                     state=raw.status if protocol == 'tcp' else None, owning_pid=pid)
            run.items.append(item)
            if remote_invalid:
                run.issue('invalid_data', 'connection remote endpoint invalid',
                          artifact_id=item.artifact_id, field='remote')
            if owner_invalid:
                run.issue('invalid_data', 'connection owner PID invalid',
                          artifact_id=item.artifact_id, field='owning_pid')
        except (KeyError, AttributeError, IndexError, TypeError, ValueError, ValidationError) as exc:
            run.issue('invalid_data', 'connection record invalid', exception_type=type(exc).__name__)
    return run.finish()
