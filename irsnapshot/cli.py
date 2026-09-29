"""Command-line interface for the current IRSnapshot milestone."""

import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from irsnapshot.analyzers.engine import analyze_snapshot
from irsnapshot.pipeline import collect_snapshot
from irsnapshot.models import CollectionStatus, InvestigationReport
from irsnapshot.reporting.console import render_console
from irsnapshot.reporting.json_report import write_json_report
from irsnapshot.reporting.process_tree import safe_text
from irsnapshot.storage import SnapshotValidationError, load_snapshot, write_snapshot

from irsnapshot import __version__


app = typer.Typer(
    name="irsnapshot",
    help="IRSnapshot Milestone 4: local Windows collection and offline snapshot analysis.",
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
