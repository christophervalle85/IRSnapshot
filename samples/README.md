# Synthetic sample provenance

`benign.snapshot.json` was hand-authored for contract testing. Nothing was collected from a real endpoint. Hostname, usernames, SIDs, paths, UUIDs, timestamps, processes, connections, tasks, and services are invented example data.

The sample contains one artifact in each of seven categories and seven successful collector records. Each collector scope explicitly says these are demonstration records. It is intentionally small and does not represent a complete Windows inventory.

The process has an absent parent, which is valid evidence for later orphan-tree handling. The network entry is a loopback listener. The disabled task retains a raw start boundary with no timezone, while its normalized timestamp stays null. The service persistence entry references the service's artifact ID.

The word `benign` describes the sample's intended illustrative use. IRSnapshot Milestone 1 performs no detection and produces no security verdict. Fixture strings are never executed.
