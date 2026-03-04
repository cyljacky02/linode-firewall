"""CLI entry point for the Linode Firewall Policy Engine."""

from __future__ import annotations

import logging
import os
import sys

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler

from lfw.cli.inspect_cmd import inspect_group
from lfw.cli.policy import policy_group
from lfw.cli.source import source_group

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def _get_token() -> str:
    load_dotenv()
    token = os.environ.get("LINODE_TOKEN", "")
    if not token:
        console.print(
            "[bold red]Error:[/] LINODE_TOKEN not set. "
            "Export it or add to .env file.",
            highlight=False,
        )
        sys.exit(1)
    return token


@click.group(name="lfw")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """lfw — Linode Firewall Policy Engine."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["get_token"] = _get_token


cli.add_command(policy_group, name="policy")
cli.add_command(source_group, name="source")
cli.add_command(inspect_group, name="inspect")


if __name__ == "__main__":
    cli()
