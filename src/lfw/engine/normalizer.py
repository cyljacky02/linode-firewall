"""CIDR normalization, de-duplication, and pre-fit checks."""

from __future__ import annotations

import ipaddress
import logging

from netaddr import IPNetwork, cidr_merge

from lfw.core.constants import MAX_ADDRESSES_PER_RULE, MAX_RULES_PER_FIREWALL
from lfw.core.exceptions import FitCheckError
from lfw.core.types import IpFamily, PrefixRecord, ResolvedPrefixSet

logger = logging.getLogger(__name__)


def normalize_cidr(raw: str) -> str | None:
    """Parse and return canonical network form, or None if invalid."""
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
        return str(net)
    except (ValueError, TypeError):
        logger.warning("Invalid CIDR skipped: %s", raw)
        return None


def normalize_and_dedup(
    records: list[PrefixRecord],
    ip_families: list[IpFamily],
) -> list[PrefixRecord]:
    """Normalize CIDRs to canonical form, filter by family, and de-duplicate."""
    family_set = set(ip_families)
    seen: dict[str, PrefixRecord] = {}

    for rec in records:
        if rec.family not in family_set:
            continue
        canonical = normalize_cidr(rec.cidr)
        if canonical is None:
            continue
        if canonical not in seen:
            seen[canonical] = PrefixRecord(
                cidr=canonical,
                family=rec.family,
                source_id=rec.source_id,
                provenance=rec.provenance,
            )

    return list(seen.values())


def collapse_exact(records: list[PrefixRecord]) -> list[PrefixRecord]:
    """Collapse exactly-adjacent/overlapping CIDRs using netaddr cidr_merge.

    Preserves provenance from the first contributing record per merged CIDR.
    """
    by_family: dict[IpFamily, list[PrefixRecord]] = {
        IpFamily.IPV4: [],
        IpFamily.IPV6: [],
    }
    for rec in records:
        by_family[rec.family].append(rec)

    result: list[PrefixRecord] = []
    for family, family_records in by_family.items():
        if not family_records:
            continue

        provenance_map: dict[str, PrefixRecord] = {
            r.cidr: r for r in family_records
        }

        nets = [IPNetwork(r.cidr) for r in family_records]
        merged = cidr_merge(nets)

        for net in merged:
            cidr_str = str(net)
            source_rec = provenance_map.get(cidr_str, family_records[0])
            result.append(
                PrefixRecord(
                    cidr=cidr_str,
                    family=family,
                    source_id=source_rec.source_id,
                    provenance=source_rec.provenance,
                )
            )

    return result


def uplift_prefixes(
    records: list[PrefixRecord],
    max_prefix: int,
) -> list[PrefixRecord]:
    """Widen CIDRs narrower than ``max_prefix`` to that boundary, then dedup.

    E.g. with ``max_prefix=24``, a /32 like ``1.2.3.4/32`` becomes
    ``1.2.3.0/24``.  Duplicates from overlapping uplifts are removed.
    """
    seen: set[str] = set()
    result: list[PrefixRecord] = []
    for rec in records:
        net = ipaddress.ip_network(rec.cidr, strict=False)
        if net.prefixlen > max_prefix:
            net = ipaddress.ip_network(
                f"{net.network_address}/{max_prefix}", strict=False
            )
        cidr = str(net)
        if cidr not in seen:
            seen.add(cidr)
            result.append(PrefixRecord(
                cidr=cidr,
                family=rec.family,
                source_id=rec.source_id,
                provenance=rec.provenance,
            ))
    return result


def build_resolved_set(
    policy_name: str,
    records: list[PrefixRecord],
    ip_families: list[IpFamily],
    snapshot_refs: list[str],
    prefix_uplift: int | None = None,
) -> ResolvedPrefixSet:
    """Full normalization pipeline: normalize → dedup → [uplift] → collapse → set."""
    raw_count = len(records)

    normalized = normalize_and_dedup(records, ip_families)

    if prefix_uplift is not None:
        pre = len(normalized)
        normalized = uplift_prefixes(normalized, prefix_uplift)
        logger.info(
            "Policy '%s': prefix uplift /%d: %d → %d CIDRs",
            policy_name, prefix_uplift, pre, len(normalized),
        )

    collapsed = collapse_exact(normalized)

    result = ResolvedPrefixSet(
        policy_name=policy_name,
        prefixes=collapsed,
        raw_count=raw_count,
        normalized_count=len(collapsed),
        snapshot_refs=snapshot_refs,
    )

    logger.info(
        "Policy '%s': %d raw → %d normalized → %d collapsed CIDRs",
        policy_name,
        raw_count,
        len(normalized),
        len(collapsed),
    )
    return result


def compute_packing_capacity(
    reserved_rules: int = 0,
    protocol_count: int = 1,
) -> int:
    """Max CIDRs that can fit in available firewall rules.

    For multi-protocol scopes (e.g. TCP+UDP), the same CIDRs are duplicated
    across protocol-specific rules, so effective rule budget is divided by
    ``protocol_count``.
    """
    available = MAX_RULES_PER_FIREWALL - reserved_rules
    if available <= 0 or protocol_count <= 0:
        return 0
    rules_per_protocol = available // protocol_count
    return rules_per_protocol * MAX_ADDRESSES_PER_RULE


def prefit_check(
    prefix_set: ResolvedPrefixSet,
    reserved_rules: int = 0,
) -> None:
    """Raise FitCheckError if the prefix set exceeds Linode packing capacity."""
    capacity = compute_packing_capacity(reserved_rules)
    ipv4_count = len(prefix_set.ipv4_cidrs)
    ipv6_count = len(prefix_set.ipv6_cidrs)
    total = ipv4_count + ipv6_count

    if total > capacity:
        raise FitCheckError(
            f"Policy '{prefix_set.policy_name}' has {total} CIDRs "
            f"({ipv4_count} IPv4 + {ipv6_count} IPv6) but capacity is "
            f"{capacity} ({MAX_RULES_PER_FIREWALL - reserved_rules} rules × "
            f"{MAX_ADDRESSES_PER_RULE} addresses/rule). "
            f"Enable summarization or reduce source scope."
        )
