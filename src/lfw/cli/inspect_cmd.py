"""CLI commands: lfw inspect firewall."""

from __future__ import annotations

import json
import logging
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lfw.adapter.linode import LinodeAdapter
from lfw.core.exceptions import LfwError
from lfw.state.db import StateDb

logger = logging.getLogger(__name__)
console = Console()


@click.group(name="inspect")
def inspect_group() -> None:
    """Inspection commands."""


@inspect_group.command(name="firewall")
@click.option("-l", "--label", required=True, help="Firewall label to inspect.")
@click.pass_context
def inspect_firewall(ctx: click.Context, label: str) -> None:
    """Show current rules, version/fingerprint, devices, and drift."""
    try:
        get_token = ctx.obj["get_token"]
        token = get_token()
        adapter = LinodeAdapter(token=token)

        info = adapter.inspect_firewall(label)
        if info is None:
            console.print(f"[red]Firewall '{label}' not found.[/]")
            sys.exit(1)

        # Basic info table
        table = Table(title=f"Firewall: {info['label']}", show_lines=True)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("ID", str(info["id"]))
        table.add_row("Status", info["status"])
        table.add_row("Tags", ", ".join(info["tags"]) or "(none)")
        table.add_row("Created", info["created"])
        table.add_row("Updated", info["updated"])
        table.add_row("Rules Hash", info["rules_hash"][:16])
        table.add_row("Devices", str(info["device_count"]))
        console.print(table)

        # Rules summary
        rules = info["rules"]
        inbound = rules.get("inbound", [])
        outbound = rules.get("outbound", [])
        console.print(Panel(
            f"Inbound: {len(inbound)} rules (policy: {rules.get('inbound_policy', 'N/A')})\n"
            f"Outbound: {len(outbound)} rules (policy: {rules.get('outbound_policy', 'N/A')})",
            title="Rules Summary",
        ))

        # Drift detection
        db = StateDb()
        last_state = db.get_last_observed_state(label)
        if last_state:
            if last_state["rules_hash"] == info["rules_hash"]:
                console.print("[green]No drift detected[/] vs last planned state.")
            else:
                console.print(
                    f"[yellow]Drift detected![/] "
                    f"Last planned hash: {last_state['rules_hash'][:16]} "
                    f"vs current: {info['rules_hash'][:16]}"
                )
        else:
            console.print("[dim]No previous planned state recorded for drift comparison.[/]")

        # Device list
        if info["devices"]:
            dev_table = Table(title="Attached Devices")
            dev_table.add_column("Device ID")
            dev_table.add_column("Type")
            dev_table.add_column("Entity ID")
            for dev in info["devices"]:
                dev_table.add_row(
                    str(dev.get("id", "")),
                    str(dev.get("type", "")),
                    str(dev.get("entity_id", "")),
                )
            console.print(dev_table)

    except LfwError as exc:
        console.print(f"[red]✗ Inspect failed:[/] {exc}")
        sys.exit(1)
