"""Command-line interface for the current IRSnapshot milestone."""

from typing import Annotated

import typer

from irsnapshot import __version__


app = typer.Typer(
    name="irsnapshot",
    help="IRSnapshot Milestone 2: offline evidence interpretation APIs.",
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
