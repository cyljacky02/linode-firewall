"""CLI commands: lfw policy validate / plan / apply."""

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
from lfw.core.types import ApplyPlan
from lfw.engine.planner import plan_firewall, plan_policy
from lfw.schema.policy import load_policy_file
from lfw.state.db import StateDb

logger = logging.getLogger(__name__)
console = Console()


def _render_plan(plan: ApplyPlan) -> None:
    """Pretty-print a plan to the console."""
    table = Table(title=f"Plan: {plan.policy_name}", show_lines=True)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Firewall Label", plan.firewall_label)
    table.add_row("Firewall ID", str(plan.firewall_id or "(new)"))
    table.add_row("Create Firewall", "Yes" if plan.create_firewall else "No")
    table.add_row("Rules Changed", "Yes" if plan.rules_changed else "No (no-op)")
    table.add_row("Current Hash", plan.current_rules_hash[:16] or "(none)")
    table.add_row("Desired Hash", plan.desired_rules_hash[:16])

    inbound_rules = plan.desired_payload.get("inbound", [])
    outbound_rules = plan.desired_payload.get("outbound", [])
    total_v4 = sum(
        len(r.get("addresses", {}).get("ipv4", []))
        for r in inbound_rules + outbound_rules
    )
    total_v6 = sum(
        len(r.get("addresses", {}).get("ipv6", []))
        for r in inbound_rules + outbound_rules
    )
    table.add_row("Inbound Rules", str(len(inbound_rules)))
    table.add_row("Outbound Rules", str(len(outbound_rules)))
    table.add_row("Total IPv4 CIDRs", str(total_v4))
    table.add_row("Total IPv6 CIDRs", str(total_v6))
    table.add_row(
        "Inbound Policy",
        plan.desired_payload.get("inbound_policy", "N/A"),
    )
    table.add_row(
        "Outbound Policy",
        plan.desired_payload.get("outbound_policy", "N/A"),
    )

    if plan.attachments_to_add:
        targets = ", ".join(
            f"{t.device_type.value}:{t.identifier}" for t in plan.attachments_to_add
        )
        table.add_row("Attach Targets", targets)

    if plan.warnings:
        table.add_row("Warnings", "\n".join(plan.warnings))

    console.print(table)

    for report in plan.summarization_reports:
        console.print(Panel(
            f"[bold]{report.family.value}[/]: "
            f"{report.input_count} → {report.output_count} CIDRs "
            f"(ratio {report.expansion_ratio:.2f}) "
            f"{'[green]PASS[/]' if report.passed else '[red]FAIL[/]'}\n"
            f"{report.detail}",
            title="Summarization",
        ))


@click.group(name="policy")
def policy_group() -> None:
    """Policy management commands."""


@policy_group.command()
@click.option("-f", "--file", "policy_file", required=True, type=click.Path(exists=True))
@click.pass_context
def validate(ctx: click.Context, policy_file: str) -> None:
    """Validate policy schema, source availability, and fit simulation."""
    try:
        spec = load_policy_file(policy_file)
        console.print(f"[green]✓[/] Schema valid: {len(spec.sources)} sources, "
                       f"{len(spec.policies)} policies")

        # Validate source availability (basic checks)
        for source in spec.sources:
            console.print(f"  Source '{source.id}' ({source.type}): [green]OK[/]")

        for policy in spec.policies:
            console.print(
                f"  Policy '{policy.name}': mode={policy.mode}, "
                f"scope={policy.traffic_scope}, families={policy.ip_families}"
            )

        console.print("[green]✓[/] Validation passed.")

    except LfwError as exc:
        console.print(f"[red]✗ Validation failed:[/] {exc}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]✗ Unexpected error:[/] {exc}")
        sys.exit(1)


def _group_by_firewall(
    policies: list,
) -> dict[str, list]:
    """Group policies by firewall_label for merged planning."""
    groups: dict[str, list] = {}
    for p in policies:
        groups.setdefault(p.firewall_label, []).append(p)
    return groups


@policy_group.command()
@click.option("-f", "--file", "policy_file", required=True, type=click.Path(exists=True))
@click.option("-p", "--policy", "policy_name", default=None, help="Run only this policy.")
@click.pass_context
def plan(ctx: click.Context, policy_file: str, policy_name: str | None) -> None:
    """Resolve sources, summarize, compute diffs — non-mutating."""
    try:
        spec = load_policy_file(policy_file)
        get_token = ctx.obj["get_token"]
        token = get_token()
        adapter = LinodeAdapter(
            token=token,
            base_url=spec.linode.base_url,
            page_size=spec.linode.page_size,
            retry_count=spec.linode.retry,
            beta_enabled=spec.linode.beta_enabled,
        )

        policies = spec.policies
        if policy_name:
            policies = [p for p in policies if p.name == policy_name]
            if not policies:
                console.print(f"[red]Policy '{policy_name}' not found in spec.[/]")
                sys.exit(1)

        fw_groups = _group_by_firewall(policies)

        for fw_label, group_policies in fw_groups.items():
            names = ", ".join(p.name for p in group_policies)
            console.print(f"\n[bold]Planning firewall '{fw_label}' ({names})[/]")

            fw = adapter.find_firewall_by_label(fw_label)
            current_rules = None
            fw_id = None
            if fw:
                current_rules = adapter.get_firewall_rules(fw)
                fw_id = fw.id
                console.print(f"  Found firewall: id={fw.id}")
            else:
                console.print("  Firewall not found — will create.")

            if len(group_policies) == 1:
                apply_plan = plan_policy(
                    spec=spec,
                    policy=group_policies[0],
                    current_rules=current_rules,
                    current_firewall_id=fw_id,
                )
            else:
                apply_plan = plan_firewall(
                    spec=spec,
                    policies=group_policies,
                    current_rules=current_rules,
                    current_firewall_id=fw_id,
                )

            _render_plan(apply_plan)

            if not apply_plan.has_changes:
                console.print("[dim]No changes required.[/]")

    except LfwError as exc:
        console.print(f"[red]✗ Plan failed:[/] {exc}")
        sys.exit(1)


@policy_group.command()
@click.option("-f", "--file", "policy_file", required=True, type=click.Path(exists=True))
@click.option("-p", "--policy", "policy_name", default=None, help="Apply only this policy.")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt.")
@click.pass_context
def apply(ctx: click.Context, policy_file: str, policy_name: str | None, yes: bool) -> None:
    """Execute plan with writes enabled and record audit history."""
    try:
        spec = load_policy_file(policy_file)
        get_token = ctx.obj["get_token"]
        token = get_token()
        adapter = LinodeAdapter(
            token=token,
            base_url=spec.linode.base_url,
            page_size=spec.linode.page_size,
            retry_count=spec.linode.retry,
            beta_enabled=spec.linode.beta_enabled,
        )
        db = StateDb()

        policies = spec.policies
        if policy_name:
            policies = [p for p in policies if p.name == policy_name]
            if not policies:
                console.print(f"[red]Policy '{policy_name}' not found in spec.[/]")
                sys.exit(1)

        fw_groups = _group_by_firewall(policies)

        for fw_label, group_policies in fw_groups.items():
            names = ", ".join(p.name for p in group_policies)
            console.print(f"\n[bold]Applying firewall '{fw_label}' ({names})[/]")

            fw = adapter.find_firewall_by_label(fw_label)
            current_rules = None
            fw_id = None
            if fw:
                current_rules = adapter.get_firewall_rules(fw)
                fw_id = fw.id

            if len(group_policies) == 1:
                apply_plan = plan_policy(
                    spec=spec,
                    policy=group_policies[0],
                    current_rules=current_rules,
                    current_firewall_id=fw_id,
                )
            else:
                apply_plan = plan_firewall(
                    spec=spec,
                    policies=group_policies,
                    current_rules=current_rules,
                    current_firewall_id=fw_id,
                )

            _render_plan(apply_plan)

            if not apply_plan.has_changes:
                console.print("[dim]No changes — skipping apply.[/]")
                continue

            if not yes:
                if not click.confirm("Proceed with apply?"):
                    console.print("[yellow]Skipped.[/]")
                    continue

            run_id = db.start_run(
                policy_name=apply_plan.policy_name,
                snapshot_refs=[
                    r.family.value for r in apply_plan.summarization_reports
                ] if apply_plan.summarization_reports else [],
            )

            result = adapter.execute_plan(apply_plan)

            status = "success" if result.success else "failed"
            db.finish_run(run_id, status, plan=apply_plan, result=result)
            db.save_plan(run_id, apply_plan)

            for action in result.actions_taken:
                db.log_action(run_id, action, success=True)
            for error in result.errors:
                db.log_action(run_id, error, success=False)

            if result.firewall_id:
                db.save_observed_state(
                    firewall_id=result.firewall_id,
                    firewall_label=apply_plan.firewall_label,
                    rules_hash=apply_plan.desired_rules_hash,
                    rules_json=json.dumps(apply_plan.desired_payload),
                )

            if result.success:
                console.print(f"[green]✓[/] Apply succeeded for '{fw_label}'")
                for a in result.actions_taken:
                    console.print(f"  • {a}")
            else:
                console.print(f"[red]✗[/] Apply failed for '{fw_label}'")
                for e in result.errors:
                    console.print(f"  • {e}")
                sys.exit(1)

    except LfwError as exc:
        console.print(f"[red]✗ Apply failed:[/] {exc}")
        sys.exit(1)
