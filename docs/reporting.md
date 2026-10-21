# Reports and investigation folders

The CLI provides four commands: `collect`, `analyze`, `report`, and `run`. Collection uses the local Windows endpoint. Analysis and reporting can use a saved snapshot offline on any supported Python host. None of these commands executes captured evidence.

## Render saved evidence

After installing the project, run:

```powershell
irsnapshot report samples/review.snapshot.json --output review.html
irsnapshot report samples/partial.snapshot.json --output partial.html
$LASTEXITCODE
```

Open the generated HTML file directly in a browser. It has embedded CSS, ordinary anchor navigation, expandable details, and print styles. There are no scripts, remote fonts, images, or CDN dependencies. Artifact paths and URLs appear as text, never active links. The Jinja2 template ships inside the wheel; a source checkout is not required to render a report.

`report` loads and validates the snapshot, analyzes it with the currently installed ruleset, and presents the resulting `InvestigationReport`. The renderer itself does not recollect, reinterpret commands, or re-evaluate rules. Rendering the same report is deterministic. The capture's tool version is preserved independently of the installed report-tool version.

The report includes:

- Summary counts, seven-source coverage, and separate analysis completeness.
- Available system facts and collecting identity, with unavailable values labelled.
- Severity-ordered findings, original evidence, and structural context.
- Process ancestry with missing/uncertain parent labels and processes referenced by findings.
- Network records with explicit ownership-association status, including unresolved owners.
- Persistence findings and an expandable inventory, with complete raw source evidence available.
- A factual UTC timeline distinguishing reported events from observed collection boundaries.
- Collection/analysis issues and expandable raw evidence.

An empty or zero-finding section is not proof of a clean endpoint. Check coverage first: a failed source is different from a successful query that returned no records. A PID match does not establish historical process ownership; scheduled trigger boundaries do not establish actual execution.

Existing output is refused unless `--overwrite` is supplied. The input snapshot cannot be the output, including through an existing symlink or hard-link alias. The output's parent directory must already exist. Publication uses a temporary sibling file, flush/sync, and atomic publication. New-file publication requires hard-link support. HTML and JSON reports each have a 128 MiB output limit.

## Complete a Windows investigation

```powershell
irsnapshot run --output investigation/
$LASTEXITCODE
```

Use a new or empty directory. A successful run produces:

| File | Contents |
|---|---|
| `snapshot.json` | Validated collected evidence and all seven coverage records |
| `analysis.json` | `InvestigationReport`, containing the original snapshot and derived analysis |
| `report.html` | Standalone human-readable presentation of that same report |
| `irsnapshot.log` | UTC progress and diagnostic messages, with controls escaped |

The order is collection, snapshot publication, analysis, JSON publication, then HTML publication. Source-level failures remain in the snapshot and do not prevent useful partial reporting. Fatal downstream failures stop the operation; any already-published snapshot remains available. The CLI does not print arbitrary raw exception messages; detailed diagnostics belong in the local log.

Logging is scoped to the operation and handlers are closed afterward. The log is initially published safely, then written incrementally as work proceeds. It is not a completed immutable evidence file while the investigation is running. There is no all-or-nothing transaction spanning the four files, and filesystem atomicity is not a power-loss or chain-of-custody guarantee.

### Reusing an output directory

Prefer a separate folder for each investigation. To intentionally reuse one:

```powershell
irsnapshot run --output investigation/ --overwrite
```

Only the four known output names are managed; unrelated files remain. Directories or symlinks occupying those reserved names are rejected before collection. Explicit overwrite replaces the log and, after successful collection, the snapshot. Old `analysis.json` and `report.html` are removed only after the new snapshot is saved, before deriving new output. If collection fails before a new snapshot is saved, earlier evidence/reports remain; the new log records the failed attempt. After stale-output cleanup succeeds, analysis or reporting failure cannot leave an earlier report in place.

A filesystem failure during stale-output cleanup stops the run and can leave an old report beside the new snapshot. Treat any failed investigation folder as incomplete: check the reported failed stage and snapshot IDs, then use the recovery commands below. The workflow does not promise an atomic transaction across multiple files.

### Recover after downstream failure

If `snapshot.json` was saved, retry the offline steps without recollecting:

```powershell
irsnapshot analyze investigation/snapshot.json --output investigation/analysis.json --overwrite
irsnapshot report investigation/snapshot.json --output investigation/report.html --overwrite
```

Inspect `irsnapshot.log` and coverage records to understand what succeeded. These recovery commands re-run the currently installed ruleset and do not append to the earlier run's log. If no snapshot was saved, resolve the collection/output failure and repeat `run` using a suitable output folder.

## Exit status

| Code | Meaning |
|---|---|
| `0` | Requested output completed with complete collection/analysis |
| `1` | Fatal I/O, platform, or runtime failure; inspect available outputs/log |
| `2` | Usage, snapshot validation, or schema failure |
| `3` | Output completed with partial/failed/skipped collection or incomplete analysis |
| `130` | Interrupted; already-published evidence remains |

Findings alone do not change a successful exit code. The review sample produces thirteen findings and exit 0. The partial sample produces eleven findings and exit 3 because its evidence coverage is incomplete.

Reports contain the original evidence and can expose usernames, paths, addresses, command arguments, and diagnostic context. Keep real investigation folders local and review content before sharing. See [operational limits](limitations.md) and [verification evidence](testing.md); live Windows collection still requires validation on Windows.
