"""Core dataclasses and type definitions for the LFW engine."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class PolicyMode(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class IpFamily(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class TrafficScope(str, Enum):
    INBOUND_TCP_UDP = "inbound_tcp_udp"
    INBOUND_TCP = "inbound_tcp"
    INBOUND_UDP = "inbound_udp"
    INBOUND_ALL = "inbound_all"
    OUTBOUND_TCP_UDP = "outbound_tcp_udp"
    OUTBOUND_TCP = "outbound_tcp"
    OUTBOUND_UDP = "outbound_udp"
    OUTBOUND_ALL = "outbound_all"
    BIDIRECTIONAL_TCP_UDP = "bidirectional_tcp_udp"


class DeviceType(str, Enum):
    LINODE = "linode"
    LINODE_INTERFACE = "linode_interface"
    NODEBALANCER = "nodebalancer"


class RuleAction(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"


# ---------------------------------------------------------------------------
# Source snapshot
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SourceSnapshot:
    """Immutable record of a fetched external source."""

    source_id: str
    source_type: str
    url_or_command: str
    sha256: str
    fetched_at: datetime
    raw_count: int
    normalized_count: int
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Prefix provenance
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PrefixRecord:
    """A single CIDR with provenance tracking."""

    cidr: str                     # canonical network string, e.g. "1.2.3.0/24"
    family: IpFamily
    source_id: str
    provenance: str = ""          # e.g. "AS3462", "TW", "x4b/vpn/ipv4"


# ---------------------------------------------------------------------------
# Resolved prefix set
# ---------------------------------------------------------------------------
@dataclass
class ResolvedPrefixSet:
    """Collection of normalized, de-duplicated prefixes for a policy."""

    policy_name: str
    prefixes: list[PrefixRecord] = field(default_factory=list)
    raw_count: int = 0
    normalized_count: int = 0
    snapshot_refs: list[str] = field(default_factory=list)  # source_id list

    @property
    def ipv4_cidrs(self) -> list[str]:
        return [p.cidr for p in self.prefixes if p.family == IpFamily.IPV4]

    @property
    def ipv6_cidrs(self) -> list[str]:
        return [p.cidr for p in self.prefixes if p.family == IpFamily.IPV6]


# ---------------------------------------------------------------------------
# Summarization
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SummarizationBounds:
    """Guardrails for the bounded-expansion summarizer."""

    max_expansion_ratio: float = 2.0
    max_supernet_width: int = 8     # max prefix bits removed per merge step
    max_prefix_loss_risk: float = 0.05


@dataclass
class SummarizationReport:
    """Full report of one summarization pass."""

    family: IpFamily
    input_count: int
    output_count: int
    expansion_ratio: float
    largest_supernet_applied: str | None = None
    dropped_prefixes: list[str] = field(default_factory=list)
    retained_prefixes: list[str] = field(default_factory=list)
    passed: bool = True
    detail: str = ""


# ---------------------------------------------------------------------------
# Rule packing
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FirewallRule:
    """A single Linode firewall rule ready for API payload."""

    action: RuleAction
    protocol: str                  # TCP, UDP, ICMP, IPENCAP
    ports: str                     # e.g. "22, 80, 443" or ""
    label: str
    description: str
    ipv4_addresses: tuple[str, ...] = ()
    ipv6_addresses: tuple[str, ...] = ()


@dataclass
class RulePack:
    """Complete set of rules for one direction (inbound/outbound)."""

    rules: list[FirewallRule] = field(default_factory=list)
    default_policy: RuleAction = RuleAction.DROP

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def to_api_payload(self) -> dict:
        """Serialize to Linode API rules format."""
        direction_rules = []
        for r in self.rules:
            entry: dict = {
                "action": r.action.value,
                "protocol": r.protocol,
                "label": r.label,
                "description": r.description,
                "addresses": {},
            }
            if r.ports:
                entry["ports"] = r.ports
            if r.ipv4_addresses:
                entry["addresses"]["ipv4"] = list(r.ipv4_addresses)
            if r.ipv6_addresses:
                entry["addresses"]["ipv6"] = list(r.ipv6_addresses)
            direction_rules.append(entry)
        return direction_rules


# ---------------------------------------------------------------------------
# Target reference
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TargetRef:
    """Reference to a Linode device to attach a firewall to."""

    device_type: DeviceType
    identifier: int | str          # Linode ID, interface ID, or NodeBalancer ID


# ---------------------------------------------------------------------------
# Plan / Apply
# ---------------------------------------------------------------------------
@dataclass
class ApplyPlan:
    """Non-mutating diff plan output."""

    policy_name: str
    firewall_label: str
    firewall_id: int | None = None
    create_firewall: bool = False
    rules_changed: bool = False
    current_rules_hash: str = ""
    desired_rules_hash: str = ""
    desired_payload: dict = field(default_factory=dict)
    attachments_to_add: list[TargetRef] = field(default_factory=list)
    attachments_to_remove: list[TargetRef] = field(default_factory=list)
    summarization_reports: list[SummarizationReport] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return (
            self.create_firewall
            or self.rules_changed
            or bool(self.attachments_to_add)
            or bool(self.attachments_to_remove)
        )


@dataclass
class ApplyResult:
    """Result of executing an apply plan."""

    policy_name: str
    success: bool
    firewall_id: int | None = None
    actions_taken: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    applied_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_RULE_COMPARE_KEYS = {"action", "protocol", "ports", "label", "description", "addresses"}


def normalize_api_rules(payload: dict) -> dict:
    """Strip Linode API-specific fields from a rules payload for comparison.

    The API response includes extra fields per rule (e.g. ``id``) that are
    absent from our generated payloads.  Normalizing both sides to the same
    key set enables accurate no-op detection.
    """
    normalized: dict = {}
    for direction in ("inbound", "outbound"):
        rules = payload.get(direction, [])
        clean_rules = []
        for rule in rules:
            if isinstance(rule, dict):
                clean = {k: rule[k] for k in _RULE_COMPARE_KEYS if k in rule}
                clean_rules.append(clean)
        normalized[direction] = clean_rules
    for policy_key in ("inbound_policy", "outbound_policy"):
        if policy_key in payload:
            normalized[policy_key] = payload[policy_key]
    return normalized


def canonical_rules_hash(payload: dict) -> str:
    """Deterministic SHA-256 of a rules payload for no-op detection.

    Automatically normalizes the payload so that Linode API responses and
    locally-generated payloads produce identical hashes when semantically equal.
    """
    cleaned = normalize_api_rules(payload)
    raw = json.dumps(cleaned, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()
