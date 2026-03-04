"""Builds Linode firewall rule payloads from summarized prefix sets."""

from __future__ import annotations

import logging

from lfw.core.constants import MAX_ADDRESSES_PER_RULE, MAX_RULES_PER_FIREWALL
from lfw.core.types import (
    FirewallRule,
    PolicyMode,
    RuleAction,
    RulePack,
    TrafficScope,
)

logger = logging.getLogger(__name__)


def _chunk_list(items: list[str], chunk_size: int) -> list[list[str]]:
    """Split a list into chunks of at most chunk_size."""
    return [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]


def _build_rules_for_cidrs(
    ipv4_cidrs: list[str],
    ipv6_cidrs: list[str],
    action: RuleAction,
    protocols: list[str],
    ports: str,
    label_prefix: str,
    description: str,
) -> list[FirewallRule]:
    """Pack CIDRs into firewall rules respecting per-rule address limits.

    Each rule can hold up to MAX_ADDRESSES_PER_RULE addresses.
    IPv4 and IPv6 addresses share the same rule when possible.
    """
    # Interleave: fill each rule with up to 255 addresses from both families
    combined_chunks: list[tuple[list[str], list[str]]] = []
    v4_flat = list(ipv4_cidrs)
    v6_flat = list(ipv6_cidrs)

    while v4_flat or v6_flat:
        v4_take = v4_flat[:MAX_ADDRESSES_PER_RULE]
        v4_flat = v4_flat[MAX_ADDRESSES_PER_RULE:]

        remaining = MAX_ADDRESSES_PER_RULE - len(v4_take)
        v6_take = v6_flat[:remaining] if remaining > 0 else []
        v6_flat = v6_flat[remaining:] if remaining > 0 else v6_flat

        combined_chunks.append((v4_take, v6_take))

    rules: list[FirewallRule] = []
    for idx, (v4_chunk, v6_chunk) in enumerate(combined_chunks):
        for proto in protocols:
            rule_label = f"{label_prefix}-{proto.lower()}-{idx + 1}"
            # Linode rule labels: max 32 chars
            rule_label = rule_label[:32]
            rules.append(
                FirewallRule(
                    action=action,
                    protocol=proto,
                    ports=ports if proto in ("TCP", "UDP") else "",
                    label=rule_label,
                    description=description,
                    ipv4_addresses=tuple(v4_chunk),
                    ipv6_addresses=tuple(v6_chunk),
                )
            )

    return rules


_SCOPE_PROTOCOLS: dict[TrafficScope, list[str]] = {
    TrafficScope.INBOUND_TCP_UDP: ["TCP", "UDP"],
    TrafficScope.INBOUND_TCP: ["TCP"],
    TrafficScope.INBOUND_UDP: ["UDP"],
    TrafficScope.INBOUND_ALL: ["TCP", "UDP", "ICMP"],
    TrafficScope.OUTBOUND_TCP_UDP: ["TCP", "UDP"],
    TrafficScope.OUTBOUND_TCP: ["TCP"],
    TrafficScope.OUTBOUND_UDP: ["UDP"],
    TrafficScope.OUTBOUND_ALL: ["TCP", "UDP", "ICMP"],
    TrafficScope.BIDIRECTIONAL_TCP_UDP: ["TCP", "UDP"],
}

_INBOUND_SCOPES = {
    TrafficScope.INBOUND_TCP_UDP,
    TrafficScope.INBOUND_TCP,
    TrafficScope.INBOUND_UDP,
    TrafficScope.INBOUND_ALL,
    TrafficScope.BIDIRECTIONAL_TCP_UDP,
}

_OUTBOUND_SCOPES = {
    TrafficScope.OUTBOUND_TCP_UDP,
    TrafficScope.OUTBOUND_TCP,
    TrafficScope.OUTBOUND_UDP,
    TrafficScope.OUTBOUND_ALL,
    TrafficScope.BIDIRECTIONAL_TCP_UDP,
}


def scope_protocol_count(scope: TrafficScope, is_nodebalancer: bool = False) -> int:
    """Return the number of distinct protocols a scope generates per direction.

    For bidirectional scopes the count is doubled (inbound + outbound).
    """
    if is_nodebalancer:
        return 1  # NodeBalancer: TCP-only, inbound-only
    protos = len(_SCOPE_PROTOCOLS.get(scope, ["TCP", "UDP"]))
    directions = int(scope in _INBOUND_SCOPES) + int(scope in _OUTBOUND_SCOPES)
    return protos * max(directions, 1)


def build_rule_pack(
    ipv4_cidrs: list[str],
    ipv6_cidrs: list[str],
    mode: PolicyMode,
    traffic_scope: TrafficScope,
    policy_name: str,
    is_nodebalancer: bool = False,
    ports: str = "1-65535",
) -> dict[str, RulePack]:
    """Build complete inbound/outbound rule packs for a policy.

    Returns dict with 'inbound' and/or 'outbound' RulePack entries.

    Design:
    - allow mode → inbound_policy=DROP, generate ACCEPT rules
    - deny mode  → inbound_policy=ACCEPT, generate DROP rules
    - NodeBalancer targets → inbound TCP-only, no outbound
    """
    if mode == PolicyMode.ALLOW:
        rule_action = RuleAction.ACCEPT
        inbound_baseline = RuleAction.DROP
        outbound_baseline = RuleAction.DROP
    else:
        rule_action = RuleAction.DROP
        inbound_baseline = RuleAction.ACCEPT
        outbound_baseline = RuleAction.ACCEPT

    protocols = (
        ["TCP"] if is_nodebalancer
        else _SCOPE_PROTOCOLS.get(traffic_scope, ["TCP", "UDP"])
    )

    label_prefix = f"lfw-{policy_name}"[:20]
    description = f"Managed by lfw policy '{policy_name}'"

    result: dict[str, RulePack] = {}

    # Inbound rules
    if traffic_scope in _INBOUND_SCOPES:
        inbound_rules = _build_rules_for_cidrs(
            ipv4_cidrs=ipv4_cidrs,
            ipv6_cidrs=ipv6_cidrs,
            action=rule_action,
            protocols=protocols,
            ports=ports,
            label_prefix=label_prefix,
            description=description,
        )
        result["inbound"] = RulePack(
            rules=inbound_rules,
            default_policy=inbound_baseline,
        )

    # Outbound rules (never for NodeBalancers)
    if traffic_scope in _OUTBOUND_SCOPES and not is_nodebalancer:
        outbound_rules = _build_rules_for_cidrs(
            ipv4_cidrs=ipv4_cidrs,
            ipv6_cidrs=ipv6_cidrs,
            action=rule_action,
            protocols=protocols,
            ports=ports,
            label_prefix=f"{label_prefix}-out",
            description=description,
        )
        result["outbound"] = RulePack(
            rules=outbound_rules,
            default_policy=outbound_baseline,
        )

    total_rules = sum(pack.rule_count for pack in result.values())
    if total_rules > MAX_RULES_PER_FIREWALL:
        logger.warning(
            "Policy '%s' generates %d rules (limit %d). "
            "Further summarization or scope reduction needed.",
            policy_name,
            total_rules,
            MAX_RULES_PER_FIREWALL,
        )

    return result


def merge_rule_packs(pack_list: list[dict[str, RulePack]]) -> dict[str, RulePack]:
    """Merge multiple policy rule packs into a single combined set.

    When multiple policies target the same firewall, their rules are
    concatenated and the most restrictive baseline policy wins (DROP > ACCEPT).
    """
    merged: dict[str, RulePack] = {}

    for packs in pack_list:
        for direction in ("inbound", "outbound"):
            if direction not in packs:
                continue
            pack = packs[direction]
            if direction not in merged:
                merged[direction] = RulePack(
                    rules=list(pack.rules),
                    default_policy=pack.default_policy,
                )
            else:
                merged[direction].rules.extend(pack.rules)
                # DROP is more restrictive — if ANY policy uses DROP baseline, use it
                if pack.default_policy == RuleAction.DROP:
                    merged[direction].default_policy = RuleAction.DROP

    total = sum(p.rule_count for p in merged.values())
    if total > MAX_RULES_PER_FIREWALL:
        logger.warning(
            "Merged firewall has %d rules (limit %d). "
            "Reduce policies or increase summarization.",
            total,
            MAX_RULES_PER_FIREWALL,
        )

    return merged


def rule_packs_to_api_payload(packs: dict[str, RulePack]) -> dict:
    """Convert rule packs to the full Linode API rules payload format."""
    payload: dict = {}

    if "inbound" in packs:
        payload["inbound"] = packs["inbound"].to_api_payload()
        payload["inbound_policy"] = packs["inbound"].default_policy.value

    if "outbound" in packs:
        payload["outbound"] = packs["outbound"].to_api_payload()
        payload["outbound_policy"] = packs["outbound"].default_policy.value

    # Fill in missing directions with empty defaults
    if "inbound" not in payload:
        payload["inbound"] = []
        payload["inbound_policy"] = "ACCEPT"
    if "outbound" not in payload:
        payload["outbound"] = []
        payload["outbound_policy"] = "ACCEPT"

    return payload
