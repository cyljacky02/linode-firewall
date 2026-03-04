"""Bounded-expansion prefix summarization engine.

Hierarchically merges prefixes into supernets to fit within Linode firewall
rule capacity, while respecting configurable guardrails per policy/family.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Sequence

from netaddr import IPNetwork, IPSet, cidr_merge

from lfw.core.constants import (
    MAX_ADDRESSES_PER_RULE,
    MAX_RULES_PER_FIREWALL,
    SUMMARIZE_DEFAULTS_ALLOW,
    SUMMARIZE_DEFAULTS_DENY,
)
from lfw.core.exceptions import SummarizationBoundsExceededError
from lfw.core.types import (
    IpFamily,
    PolicyMode,
    PrefixRecord,
    SummarizationBounds,
    SummarizationReport,
)

logger = logging.getLogger(__name__)


def _effective_bounds(
    mode: PolicyMode,
    overrides: SummarizationBounds | None,
) -> SummarizationBounds:
    """Resolve effective summarization bounds from defaults + overrides."""
    defaults = (
        SUMMARIZE_DEFAULTS_ALLOW if mode == PolicyMode.ALLOW else SUMMARIZE_DEFAULTS_DENY
    )
    if overrides is None:
        return SummarizationBounds(**defaults)
    return SummarizationBounds(
        max_expansion_ratio=overrides.max_expansion_ratio or defaults["max_expansion_ratio"],
        max_supernet_width=overrides.max_supernet_width or defaults["max_supernet_width"],
        max_prefix_loss_risk=overrides.max_prefix_loss_risk or defaults["max_prefix_loss_risk"],
    )


def _canonicalize_cidrs(cidrs: list[str]) -> list[str]:
    """Ensure all CIDRs are in strict canonical form (no host bits set).

    netaddr's cidr_merge can produce CIDRs like '10.1.4.0/21' where the
    network address has host bits set for the given prefix. Python's
    ipaddress module with strict=False strips these correctly.
    """
    result = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        result.append(str(net))
    return result


def _count_expanded_addresses(original_nets: list[IPNetwork], merged_nets: list[IPNetwork]) -> int:
    """Count how many new addresses are covered by merged set vs original."""
    original_set = IPSet(original_nets)
    merged_set = IPSet(merged_nets)
    diff = merged_set - original_set
    return diff.size


def _total_addresses(nets: Sequence[IPNetwork]) -> int:
    return sum(n.size for n in nets)


def summarize_family(
    cidrs: list[str],
    family: IpFamily,
    capacity: int,
    mode: PolicyMode,
    overrides: SummarizationBounds | None = None,
) -> tuple[list[str], SummarizationReport]:
    """Run bounded summarization for one IP family.

    Strategy: iteratively widen prefix lengths (merge supernets) until the
    CIDR count fits within capacity or guardrails are breached.
    """
    bounds = _effective_bounds(mode, overrides)
    input_count = len(cidrs)

    if input_count <= capacity:
        return _canonicalize_cidrs(cidrs), SummarizationReport(
            family=family,
            input_count=input_count,
            output_count=input_count,
            expansion_ratio=1.0,
            passed=True,
            detail="Already within capacity, no summarization needed.",
        )

    original_nets = [IPNetwork(c) for c in cidrs]
    original_total_addr = _total_addresses(original_nets)

    # Phase 1: exact cidr_merge (no expansion, just adjacent/overlapping collapse)
    current = cidr_merge(original_nets)
    if len(current) <= capacity:
        return (
            _canonicalize_cidrs([str(n) for n in current]),
            SummarizationReport(
                family=family,
                input_count=input_count,
                output_count=len(current),
                expansion_ratio=1.0,
                passed=True,
                detail="cidr_merge alone sufficient.",
            ),
        )

    # Phase 2: hierarchical supernet widening — 1 bit per step (incremental)
    largest_supernet = ""
    last_good = current  # track last result that passed guardrails
    last_good_ratio = 1.0
    last_good_step = 0

    for widen_step in range(1, bounds.max_supernet_width + 1):
        widened: list[IPNetwork] = []
        for net in current:
            new_prefix = max(net.prefixlen - 1, 0)
            widened.append(IPNetwork(f"{net.network}/{new_prefix}"))

        merged = cidr_merge(widened)

        expanded_addr = _count_expanded_addresses(original_nets, merged)
        merged_total = _total_addresses(merged)
        expansion_ratio = merged_total / original_total_addr if original_total_addr else 1.0
        loss_risk = expanded_addr / merged_total if merged_total else 0.0

        if expansion_ratio > bounds.max_expansion_ratio:
            logger.debug(
                "Widen step %d: expansion ratio %.2f exceeds bound %.2f — stopping",
                widen_step,
                expansion_ratio,
                bounds.max_expansion_ratio,
            )
            break

        if loss_risk > bounds.max_prefix_loss_risk:
            logger.debug(
                "Widen step %d: loss risk %.4f exceeds bound %.4f — stopping",
                widen_step,
                loss_risk,
                bounds.max_prefix_loss_risk,
            )
            break

        current = merged
        last_good = merged
        last_good_ratio = expansion_ratio
        last_good_step = widen_step
        largest_supernet = f"/{min(n.prefixlen for n in merged)}"

        if len(current) <= capacity:
            return (
                _canonicalize_cidrs([str(n) for n in current]),
                SummarizationReport(
                    family=family,
                    input_count=input_count,
                    output_count=len(current),
                    expansion_ratio=expansion_ratio,
                    largest_supernet_applied=largest_supernet,
                    passed=True,
                    detail=f"Summarized in {widen_step} widen step(s).",
                ),
            )

    # Phase 2b: iterative targeted overflow elimination
    # Repeatedly widen all current CIDRs by 1 bit (most-specific first),
    # re-merge, and check guardrails each round. More effective than uniform
    # widening because each iteration only grows from the current compressed set.
    targeted_steps = 0
    while len(current) > capacity and targeted_steps < bounds.max_supernet_width:
        targeted_steps += 1
        prev_count = len(current)

        widened = []
        for net in current:
            new_plen = max(net.prefixlen - 1, 0)
            widened.append(IPNetwork(f"{net.network}/{new_plen}"))

        candidate = cidr_merge(widened)

        candidate_total = _total_addresses(candidate)
        candidate_ratio = candidate_total / original_total_addr if original_total_addr else 1.0

        if candidate_ratio > bounds.max_expansion_ratio:
            logger.debug(
                "Targeted step %d: ratio %.2f exceeds bound %.2f — stopping",
                targeted_steps,
                candidate_ratio,
                bounds.max_expansion_ratio,
            )
            break

        current = candidate
        last_good = candidate
        last_good_ratio = candidate_ratio
        last_good_step += 1

        if len(current) >= prev_count:
            logger.debug("Targeted step %d: no progress (%d CIDRs)", targeted_steps, len(current))
            break

        if len(current) <= capacity:
            largest_supernet = f"/{min(n.prefixlen for n in current)}"
            return (
                _canonicalize_cidrs([str(n) for n in current]),
                SummarizationReport(
                    family=family,
                    input_count=input_count,
                    output_count=len(current),
                    expansion_ratio=candidate_ratio,
                    largest_supernet_applied=largest_supernet,
                    passed=True,
                    detail=(
                        f"Summarized: {last_good_step} total widen step(s) "
                        f"({targeted_steps} in targeted phase)."
                    ),
                ),
            )

    # Failed to fit within bounds — report best effort
    output_count = len(last_good)
    raise SummarizationBoundsExceededError(
        input_count=input_count,
        output_count=output_count,
        capacity=capacity,
        detail=(
            f"After {last_good_step} uniform step(s) + targeted widen "
            f"(max {bounds.max_supernet_width}): "
            f"{output_count} CIDRs remain (need ≤ {capacity}, "
            f"ratio={last_good_ratio:.2f}). "
            f"Remediation: increase max_expansion_ratio/max_supernet_width, "
            f"reduce source scope, or split across multiple firewalls."
        ),
    )


def summarize_prefix_set(
    ipv4_cidrs: list[str],
    ipv6_cidrs: list[str],
    mode: PolicyMode,
    max_rules_for_policy: int = MAX_RULES_PER_FIREWALL,
    overrides: SummarizationBounds | None = None,
) -> tuple[list[str], list[str], list[SummarizationReport]]:
    """Summarize both families, allocating rule capacity between them.

    Returns (summarized_ipv4, summarized_ipv6, reports).
    """
    reports: list[SummarizationReport] = []

    # Allocate rules: split proportionally, min 1 rule per family if non-empty
    total_cidrs = len(ipv4_cidrs) + len(ipv6_cidrs)
    if total_cidrs == 0:
        return [], [], []

    if ipv4_cidrs and ipv6_cidrs:
        v4_share = max(1, round(max_rules_for_policy * len(ipv4_cidrs) / total_cidrs))
        v6_share = max(1, max_rules_for_policy - v4_share)
    elif ipv4_cidrs:
        v4_share = max_rules_for_policy
        v6_share = 0
    else:
        v4_share = 0
        v6_share = max_rules_for_policy

    result_v4 = ipv4_cidrs
    result_v6 = ipv6_cidrs

    if ipv4_cidrs:
        v4_capacity = v4_share * MAX_ADDRESSES_PER_RULE
        result_v4, report_v4 = summarize_family(
            ipv4_cidrs, IpFamily.IPV4, v4_capacity, mode, overrides
        )
        reports.append(report_v4)

    if ipv6_cidrs:
        v6_capacity = v6_share * MAX_ADDRESSES_PER_RULE
        result_v6, report_v6 = summarize_family(
            ipv6_cidrs, IpFamily.IPV6, v6_capacity, mode, overrides
        )
        reports.append(report_v6)

    return result_v4, result_v6, reports
