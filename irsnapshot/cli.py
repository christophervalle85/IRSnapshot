"""Command-line interface for the current IRSnapshot milestone."""

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from irsnapshot.analyzers.engine import analyze_snapshot
from irsnapshot.pipeline import collect_snapshot
from irsnapshot.investigation import InvestigationError, InvestigationInterrupted, run_investigation
from irsnapshot.reporting.html_report import write_html_report
from irsnapshot.models import CollectionStatus, InvestigationReport
from irsnapshot.reporting.console import render_console
from irsnapshot.reporting.json_report import write_json_report
from irsnapshot.reporting.process_tree import safe_text
from irsnapshot.storage import SnapshotValidationError, load_snapshot, write_snapshot

from irsnapshot import __version__


app = typer.Typer(
    name="irsnapshot",
    help="IRSnapshot Milestone 5: local Windows investigation and offline reports.",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
)


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"IRSnapshot {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    context: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_show_version,
            is_eager=True,
            help="Show the IRSnapshot version and exit.",
        ),
    ] = False,
) -> None:
    """Show the milestone's available command-line options."""
    if context.invoked_subcommand is None and not version:
        typer.echo(context.get_help())


class _InputAliasError(ValueError):
    pass


def _guard_input(source: Path, output: Path) -> None:
    # resolve also catches aliases through directory symlinks and relative paths.
    if source.resolve() == output.resolve() or (output.exists() and source.samefile(output)):
        raise _InputAliasError('Report output must not overwrite the input snapshot, including aliases.')


@app.command()
def collect(
    output: Annotated[Path, typer.Option('--output', help='Save the collected snapshot as UTF-8 JSON.')],
    overwrite: Annotated[bool, typer.Option('--overwrite', help='Replace an existing snapshot destination.')] = False,
) -> None:
    """Collect local Windows evidence and save one validated snapshot."""
    # This early guard avoids endpoint calls for an already occupied destination.
    # write_snapshot repeats the no-clobber check atomically at publication time.
    if os.path.lexists(output):
        if not overwrite:
            typer.echo(f'Output already exists: {safe_text(str(output))}. Use --overwrite to replace it.', err=True)
            raise typer.Exit(1)
    try:
        snapshot = collect_snapshot()
        write_snapshot(snapshot, output, overwrite=overwrite)
    except KeyboardInterrupt:
        typer.echo('Collection interrupted.', err=True)
        raise typer.Exit(130)
    except Exception as exc:
        from irsnapshot.collectors.windows import UnsupportedPlatformError
        if isinstance(exc, UnsupportedPlatformError):
            typer.echo(safe_text(str(exc)), err=True)
        else:
            typer.echo(f'Collection failed ({type(exc).__name__}). Check the platform and output path.', err=True)
        raise typer.Exit(1)
    typer.echo(f'Collection {snapshot.snapshot_id} saved to {safe_text(str(output))}')
    system_info = snapshot.system
    username = safe_text(system_info.collector_username) if system_info and system_info.collector_username else 'unavailable'
    sid = safe_text(system_info.collector_sid) if system_info and system_info.collector_sid else 'unavailable'
    elevated = ('unavailable' if system_info is None or system_info.elevated is None
                else 'yes' if system_info.elevated else 'no')
    typer.echo(f'Collector identity: {username}; SID: {sid}; elevated: {elevated}')
    typer.echo('Coverage: ' + '; '.join(
        f'{run.collector.value} {run.status.value} '
        f'({run.item_count} item{"s" if run.item_count != 1 else ""}, '
        f'{len(run.issues)} issue{"s" if len(run.issues) != 1 else ""})'
        for run in snapshot.collector_runs))
    partial = any(run.status != CollectionStatus.OK for run in snapshot.collector_runs)
    if partial:
        typer.echo('Analyze saved snapshot to inspect issues.')
    raise typer.Exit(3 if partial else 0)


@app.command()
def analyze(
    snapshot: Annotated[Path, typer.Argument(help='Existing UTF-8 snapshot JSON to analyze offline.')],
    output: Annotated[Path | None, typer.Option('--output', help='Save the original snapshot and analysis as JSON.')] = None,
    overwrite: Annotated[bool, typer.Option('--overwrite', help='Replace an existing report destination; never the input snapshot.')] = False,
) -> None:
    """Analyze captured evidence and print findings, coverage, and relationships."""
    if overwrite and output is None:
        raise typer.BadParameter('--overwrite requires --output')
    try:
        original = load_snapshot(snapshot)
        if output is not None:
            _guard_input(snapshot, output)
        result = analyze_snapshot(original)
        report = InvestigationReport(snapshot=original, analysis=result)
        if output is not None:
            _guard_input(snapshot, output)
            write_json_report(report, output, overwrite=overwrite)
        render_console(report, Console())
    except KeyboardInterrupt:
        typer.echo('Analysis interrupted.', err=True)
        raise typer.Exit(130)
    except (SnapshotValidationError, _InputAliasError) as exc:
        typer.echo(safe_text(str(exc)), err=True)
        raise typer.Exit(2)
    except Exception as exc:
        # Do not echo raw validation values or exception text from evidence.
        typer.echo(f'Analysis failed ({type(exc).__name__}). Check the input and output paths and available storage.', err=True)
        raise typer.Exit(1)
    partial = not result.complete or any(run.status != CollectionStatus.OK for run in original.collector_runs)
    raise typer.Exit(3 if partial else 0)


def _report_partial(report: InvestigationReport) -> bool:
    return not report.analysis.complete or any(run.status != CollectionStatus.OK for run in report.snapshot.collector_runs)


def _report_summary(report: InvestigationReport, output: Path) -> None:
    partial = _report_partial(report)
    typer.echo(f'Investigation {report.snapshot.snapshot_id}; output: {safe_text(str(output))}')
    typer.echo('Outcome: ' + ('partial investigation' if partial else 'complete investigation')
               + f'; {len(report.analysis.findings)} findings; analysis '
               + ('complete' if report.analysis.complete else 'incomplete'))
    typer.echo('Coverage: ' + '; '.join(
        f'{run.collector.value} {run.status.value} ({run.item_count} items, {len(run.issues)} issues)'
        for run in report.snapshot.collector_runs))
    if not report.analysis.findings:
        typer.echo('No findings from supported rules and available evidence; this is not malware clearance.')


@app.command()
def report(
    snapshot: Annotated[Path, typer.Argument(help='Existing UTF-8 snapshot JSON to report offline.')],
    output: Annotated[Path, typer.Option('--output', help='Save a standalone HTML analyst report.')],
    overwrite: Annotated[bool, typer.Option('--overwrite', help='Replace an existing report; never the input snapshot.')] = False,
) -> None:
    """Analyze a saved snapshot and publish standalone HTML without collection."""
    try:
        original = load_snapshot(snapshot)
        _guard_input(snapshot, output)
        result = InvestigationReport(snapshot=original, analysis=analyze_snapshot(original))
        _guard_input(snapshot, output)
        write_html_report(result, output, overwrite=overwrite)
        _report_summary(result, output)
    except KeyboardInterrupt:
        typer.echo('Report interrupted.', err=True)
        raise typer.Exit(130)
    except (SnapshotValidationError, _InputAliasError) as exc:
        typer.echo(safe_text(str(exc)), err=True)
        raise typer.Exit(2)
    except Exception as exc:
        typer.echo(f'Report failed ({type(exc).__name__}). Check the input and output paths and available storage.', err=True)
        raise typer.Exit(1)
    raise typer.Exit(3 if _report_partial(result) else 0)


@app.command()
def run(
    output: Annotated[Path, typer.Option('--output', help='Save snapshot, JSON analysis, HTML report and local log in this directory.')],
    overwrite: Annotated[bool, typer.Option('--overwrite', help='Replace reserved artifacts while preserving unrelated files.')] = False,
) -> None:
    """Collect local Windows evidence, preserve the snapshot and publish reports."""
    try:
        result = run_investigation(output, overwrite=overwrite)
        _report_summary(result, output)
    except KeyboardInterrupt as exc:
        typer.echo('Investigation interrupted.', err=True)
        if isinstance(exc, InvestigationInterrupted) and exc.snapshot_path is not None:
            typer.echo(f'Snapshot preserved: {safe_text(str(exc.snapshot_path))}', err=True)
        raise typer.Exit(130)
    except Exception as exc:
        from irsnapshot.collectors.windows import UnsupportedPlatformError
        cause = exc.__cause__ if isinstance(exc, InvestigationError) else exc
        if isinstance(cause, UnsupportedPlatformError):
            typer.echo('Live collection requires Windows 10/11 x64 and 64-bit Python. Use analyze or report with a saved snapshot on this host.', err=True)
        elif isinstance(exc, InvestigationError):
            typer.echo(f'Investigation failed during {exc.stage}. Check irsnapshot.log and available storage.', err=True)
        else:
            typer.echo('Investigation could not start. Use a new or empty output directory, or --overwrite; check reserved artifact names and available storage.', err=True)
        if isinstance(exc, InvestigationError) and exc.snapshot_path is not None:
            typer.echo(f'Snapshot preserved: {safe_text(str(exc.snapshot_path))}', err=True)
        raise typer.Exit(1)
    raise typer.Exit(3 if _report_partial(result) else 0)
