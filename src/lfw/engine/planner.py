"""Orchestrates source resolution → normalization → summarization → planning."""

from __future__ import annotations

import logging

from lfw.core.constants import MAX_RULES_PER_FIREWALL
from lfw.core.types import (
    ApplyPlan,
    DeviceType,
    IpFamily,
    PolicyMode,
    PrefixRecord,
    SummarizationBounds,
    TargetRef,
    TrafficScope,
    canonical_rules_hash,
)
from lfw.engine.normalizer import build_resolved_set
from lfw.engine.rule_builder import (
    build_rule_pack,
    merge_rule_packs,
    rule_packs_to_api_payload,
    scope_protocol_count,
)
from lfw.engine.summarizer import summarize_prefix_set
from lfw.schema.policy import PolicyConfig, PolicySpec
from lfw.sources.factory import create_provider

logger = logging.getLogger(__name__)


def resolve_sources(
    spec: PolicySpec,
    policy: PolicyConfig,
) -> tuple[list[PrefixRecord], list[str]]:
    """Fetch and merge all sources referenced by a policy."""
    source_map = {s.id: s for s in spec.sources}
    all_records: list[PrefixRecord] = []
    snapshot_refs: list[str] = []

    for src_id in policy.source_ids:
        source_cfg = source_map[src_id]
        provider = create_provider(source_cfg)
        snapshot, records = provider.fetch()
        all_records.extend(records)
        snapshot_refs.append(snapshot.source_id)
        logger.info(
            "Source '%s': %d records fetched (sha256=%s)",
            src_id,
            len(records),
            snapshot.sha256[:12],
        )

    return all_records, snapshot_refs


def plan_policy(
    spec: PolicySpec,
    policy: PolicyConfig,
    current_rules: dict | None = None,
    current_firewall_id: int | None = None,
) -> ApplyPlan:
    """Generate a non-mutating plan for a single policy.

    Steps:
    1. Resolve sources → raw prefix records
    2. Normalize + de-duplicate + collapse
    3. Pre-fit check
    4. Summarize if needed
    5. Build rule packs
    6. Diff against current state
    """
    mode = PolicyMode(policy.mode)
    families = [IpFamily(f) for f in policy.ip_families]
    scope = TrafficScope(policy.traffic_scope)
    is_nb = any(t.type == "nodebalancer" for t in policy.targets)

    # Step 1: resolve sources
    records, snapshot_refs = resolve_sources(spec, policy)

    # Step 2: normalize (with optional prefix uplift)
    prefix_set = build_resolved_set(
        policy_name=policy.name,
        records=records,
        ip_families=families,
        snapshot_refs=snapshot_refs,
        prefix_uplift=policy.prefix_uplift,
    )

    # Step 3: derive protocol-aware rule budget
    proto_count = scope_protocol_count(scope, is_nodebalancer=is_nb)

    ipv4_cidrs = prefix_set.ipv4_cidrs
    ipv6_cidrs = prefix_set.ipv6_cidrs

    # Step 4: summarize with protocol-aware capacity
    summarization_reports = []
    if policy.summarization.enabled:
        overrides = None
        if any([
            policy.summarization.max_expansion_ratio,
            policy.summarization.max_supernet_width,
            policy.summarization.max_prefix_loss_risk,
        ]):
            overrides = SummarizationBounds(
                max_expansion_ratio=policy.summarization.max_expansion_ratio or 2.0,
                max_supernet_width=policy.summarization.max_supernet_width or 8,
                max_prefix_loss_risk=policy.summarization.max_prefix_loss_risk or 0.05,
            )

        effective_rules = MAX_RULES_PER_FIREWALL // max(proto_count, 1)
        ipv4_cidrs, ipv6_cidrs, summarization_reports = summarize_prefix_set(
            ipv4_cidrs=ipv4_cidrs,
            ipv6_cidrs=ipv6_cidrs,
            mode=mode,
            max_rules_for_policy=effective_rules,
            overrides=overrides,
        )

    # Step 5: build rules
    rule_packs = build_rule_pack(
        ipv4_cidrs=ipv4_cidrs,
        ipv6_cidrs=ipv6_cidrs,
        mode=mode,
        traffic_scope=scope,
        policy_name=policy.name,
        is_nodebalancer=is_nb,
        ports=policy.ports,
    )

    desired_payload = rule_packs_to_api_payload(rule_packs)
    desired_hash = canonical_rules_hash(desired_payload)

    # Step 6: diff
    current_hash = ""
    rules_changed = True
    if current_rules is not None:
        current_hash = canonical_rules_hash(current_rules)
        rules_changed = current_hash != desired_hash

    # Build plan
    attachments_to_add = [
        TargetRef(device_type=DeviceType(t.type), identifier=t.id)
        for t in policy.targets
    ]

    plan = ApplyPlan(
        policy_name=policy.name,
        firewall_label=policy.firewall_label,
        firewall_id=current_firewall_id,
        create_firewall=current_firewall_id is None,
        rules_changed=rules_changed,
        current_rules_hash=current_hash,
        desired_rules_hash=desired_hash,
        desired_payload=desired_payload,
        attachments_to_add=attachments_to_add,
        summarization_reports=summarization_reports,
    )

    if not rules_changed:
        logger.info("Policy '%s': no rule changes detected (no-op).", policy.name)
    else:
        total_rules = sum(
            len(desired_payload.get(d, [])) for d in ("inbound", "outbound")
        )
        logger.info(
            "Policy '%s': %d rules planned (%d IPv4 + %d IPv6 CIDRs).",
            policy.name,
            total_rules,
            len(ipv4_cidrs),
            len(ipv6_cidrs),
        )

    return plan


def _build_policy_rule_packs(
    spec: PolicySpec,
    policy: PolicyConfig,
    max_rules: int | None = None,
) -> tuple[dict, list]:
    """Resolve sources and build rule packs for a single policy (no diff).

    When ``max_rules`` is provided (by ``plan_firewall``), it overrides the
    default full-firewall budget so that multiple policies can share the
    25-rule limit.
    """
    mode = PolicyMode(policy.mode)
    families = [IpFamily(f) for f in policy.ip_families]
    scope = TrafficScope(policy.traffic_scope)
    is_nb = any(t.type == "nodebalancer" for t in policy.targets)

    records, snapshot_refs = resolve_sources(spec, policy)
    prefix_set = build_resolved_set(
        policy_name=policy.name,
        records=records,
        ip_families=families,
        snapshot_refs=snapshot_refs,
        prefix_uplift=policy.prefix_uplift,
    )

    proto_count = scope_protocol_count(scope, is_nodebalancer=is_nb)
    ipv4_cidrs = prefix_set.ipv4_cidrs
    ipv6_cidrs = prefix_set.ipv6_cidrs

    summarization_reports = []
    if policy.summarization.enabled:
        overrides = None
        if any([
            policy.summarization.max_expansion_ratio,
            policy.summarization.max_supernet_width,
            policy.summarization.max_prefix_loss_risk,
        ]):
            overrides = SummarizationBounds(
                max_expansion_ratio=policy.summarization.max_expansion_ratio or 2.0,
                max_supernet_width=policy.summarization.max_supernet_width or 8,
                max_prefix_loss_risk=policy.summarization.max_prefix_loss_risk or 0.05,
            )
        if max_rules is not None:
            effective_rules = max_rules // max(proto_count, 1)
        else:
            effective_rules = MAX_RULES_PER_FIREWALL // max(proto_count, 1)
        ipv4_cidrs, ipv6_cidrs, summarization_reports = summarize_prefix_set(
            ipv4_cidrs=ipv4_cidrs,
            ipv6_cidrs=ipv6_cidrs,
            mode=mode,
            max_rules_for_policy=effective_rules,
            overrides=overrides,
        )

    rule_packs = build_rule_pack(
        ipv4_cidrs=ipv4_cidrs,
        ipv6_cidrs=ipv6_cidrs,
        mode=mode,
        traffic_scope=scope,
        policy_name=policy.name,
        is_nodebalancer=is_nb,
        ports=policy.ports,
    )

    return rule_packs, summarization_reports


def _count_pack_rules(packs: dict) -> int:
    """Count total rules across all directions in a rule pack dict."""
    total = 0
    for pack in packs.values():
        total += pack.rule_count if hasattr(pack, "rule_count") else len(pack)
    return total


def plan_firewall(
    spec: PolicySpec,
    policies: list[PolicyConfig],
    current_rules: dict | None = None,
    current_firewall_id: int | None = None,
) -> ApplyPlan:
    """Plan a single firewall from one or more policies sharing the same label.

    Uses two-pass planning when multiple policies share a firewall:
    - Pass 1: build each policy unconstrained to learn rule counts
    - Pass 2: if total > 25, re-plan with proportionally allocated budgets
    """
    if not policies:
        raise ValueError("No policies provided for firewall planning")

    firewall_label = policies[0].firewall_label
    policy_names = [p.name for p in policies]

    all_attachments: list[TargetRef] = []
    for policy in policies:
        all_attachments.extend(
            TargetRef(device_type=DeviceType(t.type), identifier=t.id)
            for t in policy.targets
        )

    # Pass 1: unconstrained build
    pass1_packs: list[dict] = []
    pass1_reports: list = []
    for policy in policies:
        packs, reports = _build_policy_rule_packs(spec, policy)
        pass1_packs.append(packs)
        pass1_reports.extend(reports)

    pass1_rule_counts = [_count_pack_rules(p) for p in pass1_packs]
    total_pass1 = sum(pass1_rule_counts)

    if total_pass1 <= MAX_RULES_PER_FIREWALL:
        # Fits — use pass 1 results directly
        all_rule_packs = pass1_packs
        all_reports = pass1_reports
    else:
        # Pass 2: re-plan with proportional budgets
        logger.info(
            "Firewall '%s': pass 1 produced %d rules (limit %d), "
            "re-planning with budget allocation.",
            firewall_label, total_pass1, MAX_RULES_PER_FIREWALL,
        )
        budgets: list[int] = []
        for count in pass1_rule_counts:
            share = max(1, round(MAX_RULES_PER_FIREWALL * count / total_pass1))
            budgets.append(share)

        # Adjust to ensure sum == 25: trim the largest budget
        while sum(budgets) > MAX_RULES_PER_FIREWALL:
            largest_idx = budgets.index(max(budgets))
            budgets[largest_idx] -= 1
        while sum(budgets) < MAX_RULES_PER_FIREWALL:
            smallest_idx = budgets.index(min(budgets))
            budgets[smallest_idx] += 1

        all_rule_packs = []
        all_reports = []
        for policy, budget in zip(policies, budgets):
            logger.info(
                "  Policy '%s': allocated %d rules (was %d unconstrained).",
                policy.name, budget,
                pass1_rule_counts[policies.index(policy)],
            )
            packs, reports = _build_policy_rule_packs(spec, policy, max_rules=budget)
            all_rule_packs.append(packs)
            all_reports.extend(reports)

    merged_packs = merge_rule_packs(all_rule_packs) if len(all_rule_packs) > 1 else all_rule_packs[0]
    desired_payload = rule_packs_to_api_payload(merged_packs)
    desired_hash = canonical_rules_hash(desired_payload)

    current_hash = ""
    rules_changed = True
    if current_rules is not None:
        current_hash = canonical_rules_hash(current_rules)
        rules_changed = current_hash != desired_hash

    combined_name = " + ".join(policy_names)
    plan = ApplyPlan(
        policy_name=combined_name,
        firewall_label=firewall_label,
        firewall_id=current_firewall_id,
        create_firewall=current_firewall_id is None,
        rules_changed=rules_changed,
        current_rules_hash=current_hash,
        desired_rules_hash=desired_hash,
        desired_payload=desired_payload,
        attachments_to_add=all_attachments,
        summarization_reports=all_reports,
    )

    total_rules = sum(len(desired_payload.get(d, [])) for d in ("inbound", "outbound"))
    if not rules_changed:
        logger.info("Firewall '%s': no changes (no-op).", firewall_label)
    else:
        logger.info(
            "Firewall '%s': %d rules from %d policies.",
            firewall_label,
            total_rules,
            len(policies),
        )

    return plan
