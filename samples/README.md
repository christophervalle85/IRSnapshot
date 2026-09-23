# Synthetic sample provenance

`benign.snapshot.json` was hand-authored for contract testing. Nothing was collected from a real endpoint. Hostname, usernames, SIDs, paths, UUIDs, timestamps, processes, connections, tasks, and services are invented example data.

The sample contains one artifact in each of seven categories and seven successful collector records. Each collector scope explicitly says these are demonstration records. It is intentionally small and does not represent a complete Windows inventory.

The process has an absent parent, which is valid evidence for later orphan-tree handling. The network entry is a loopback listener. The disabled task retains a raw start boundary with no timezone, while its normalized timestamp stays null. The service persistence entry references the service's artifact ID.

The word `benign` describes the sample's intended illustrative use. The current ruleset produces no findings for it; that result is not a security verdict. The sample retains its original capture-tool version `0.1.0`, while the new fixtures below use `0.3.0`. All use schema `1.0`. Fixture strings are never executed.

## Review walkthrough

`review.snapshot.json` extends the invented inventory with ten processes, including an Office parent and three direct shell/script-host children. Encoded and hidden-window PowerShell options, TEMP/AppData executables, and narrow certutil/rundll32/regsvr32 patterns exercise all ten process rules. The encoded string represents a harmless synthetic output command and remains opaque to the analyzer.

A Run value, disabled task, and stopped service exercise the three persistence rules. The task has two matching actions; it produces one finding retaining both actions as evidence. Service/task persistence projections remain in inventory and do not duplicate source-artifact findings. The expected total is **13 findings**, exactly one per rule.

Remote URL strings use reserved `.invalid` domains; the IPv6 remote endpoint uses a documentation address. These are data for matching and presentation, never connection targets. One connection has an absent owner to demonstrate an unresolved association. Directory roots and owner-scoped environment values are captured fixture context, not assumptions about the analyst's machine.

## Partial walkthrough

`partial.snapshot.json` uses the same invented scenario with failed system and network collection and a denied command-line field for PID 420. It contains no system artifact or network records, with matching failure records. Other process fields survive. P001/P002 cannot match the absent command; the remaining **11 findings** remain available. The timeline does not invent a boot event.

The rules can finish successfully (`analysis.complete=true`) even when collection was incomplete. The command exits **3** and displays the collection issues. This distinguishes evaluation success from evidence coverage.
