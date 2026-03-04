"""CLI commands: lfw source refresh."""

from __future__ import annotations

import logging
import sys

import click
from rich.console import Console

from lfw.core.exceptions import LfwError
from lfw.sources.factory import create_provider
from lfw.schema.policy import load_policy_file
from lfw.state.db import StateDb

logger = logging.getLogger(__name__)
console = Console()


@click.group(name="source")
def source_group() -> None:
    """Source management commands."""


@source_group.command()
@click.option("-f", "--file", "policy_file", required=True, type=click.Path(exists=True))
@click.option("-s", "--source", "source_id", default="all", help="Source ID or 'all'.")
@click.pass_context
def refresh(ctx: click.Context, policy_file: str, source_id: str) -> None:
    """Refresh raw source snapshots into SQLite cache."""
    try:
        spec = load_policy_file(policy_file)
        db = StateDb()

        sources = spec.sources
        if source_id != "all":
            sources = [s for s in sources if s.id == source_id]
            if not sources:
                console.print(f"[red]Source '{source_id}' not found in spec.[/]")
                sys.exit(1)

        for source_cfg in sources:
            console.print(f"[bold]Refreshing source: {source_cfg.id}[/]")
            try:
                provider = create_provider(source_cfg)
                snapshot, records = provider.fetch()

                snapshot_db_id = db.save_snapshot(snapshot)
                console.print(
                    f"  [green]✓[/] {snapshot.normalized_count} CIDRs "
                    f"(sha256={snapshot.sha256[:12]}, db_id={snapshot_db_id})"
                )

            except LfwError as exc:
                console.print(f"  [red]✗[/] {exc}")
                if spec.execution.fail_on_warnings:
                    sys.exit(1)

    except LfwError as exc:
        console.print(f"[red]✗ Source refresh failed:[/] {exc}")
        sys.exit(1)
