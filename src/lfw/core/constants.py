"""Linode API and engine constants."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Linode Cloud Firewall hard limits
# ---------------------------------------------------------------------------
MAX_RULES_PER_FIREWALL = 25          # inbound + outbound combined
MAX_ADDRESSES_PER_RULE = 255         # IPv4/IPv6 CIDRs per rule
MAX_PORTS_PER_RULE = 15              # port entries (ranges count as 2)

# Derived packing capacities
MAX_CIDRS_PER_FIREWALL = MAX_RULES_PER_FIREWALL * MAX_ADDRESSES_PER_RULE  # 6375

# ---------------------------------------------------------------------------
# Default Linode API settings
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "https://api.linode.com/v4"
BETA_BASE_URL = "https://api.linode.com/v4beta"
DEFAULT_PAGE_SIZE = 100
DEFAULT_RETRY_COUNT = 3

# ---------------------------------------------------------------------------
# Summarization defaults — stricter for allow, relaxed for deny
# ---------------------------------------------------------------------------
SUMMARIZE_DEFAULTS_ALLOW = {
    "max_expansion_ratio": 1.5,
    "max_supernet_width": 8,
    "max_prefix_loss_risk": 0.40,
}

SUMMARIZE_DEFAULTS_DENY = {
    "max_expansion_ratio": 4.0,
    "max_supernet_width": 12,
    "max_prefix_loss_risk": 0.80,
}

# ---------------------------------------------------------------------------
# Source identifiers
# ---------------------------------------------------------------------------
SOURCE_TYPE_X4B = "x4b_list"
SOURCE_TYPE_ASN = "asn_bgpq4"
SOURCE_TYPE_COUNTRY = "country_geolite"
SOURCE_TYPE_CLOUDFLARE = "cloudflare_ips"

# ---------------------------------------------------------------------------
# Traffic / protocol
# ---------------------------------------------------------------------------
VALID_PROTOCOLS = ("TCP", "UDP", "ICMP", "IPENCAP")
VALID_ACTIONS = ("ACCEPT", "DROP")
VALID_TRAFFIC_SCOPES = (
    "inbound_tcp_udp",
    "inbound_tcp",
    "inbound_udp",
    "inbound_all",
    "outbound_tcp_udp",
    "outbound_tcp",
    "outbound_udp",
    "outbound_all",
    "bidirectional_tcp_udp",
)
VALID_IP_FAMILIES = ("ipv4", "ipv6")
VALID_MODES = ("allow", "deny")
VALID_DEVICE_TYPES = ("linode", "linode_interface", "nodebalancer")
