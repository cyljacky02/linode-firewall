"""Pydantic models for policy YAML validation."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from lfw.core.constants import (
    DEFAULT_BASE_URL,
    DEFAULT_PAGE_SIZE,
    DEFAULT_RETRY_COUNT,
)


# ---------------------------------------------------------------------------
# Linode connection settings
# ---------------------------------------------------------------------------
class LinodeSettings(BaseModel):
    base_url: str = DEFAULT_BASE_URL
    page_size: int = Field(default=DEFAULT_PAGE_SIZE, ge=25, le=500)
    retry: int = Field(default=DEFAULT_RETRY_COUNT, ge=0, le=10)
    beta_enabled: bool = False


# ---------------------------------------------------------------------------
# Source definitions
# ---------------------------------------------------------------------------
class X4bListSource(BaseModel):
    id: str
    type: Literal["x4b_list"] = "x4b_list"
    list_paths: list[str] = Field(default_factory=lambda: ["output/vpn/ipv4.txt"])
    base_url: str = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main"


class AsnBgpq4Source(BaseModel):
    id: str
    type: Literal["asn_bgpq4"] = "asn_bgpq4"
    asn: str  # e.g. "AS3462"
    bgpq4_path: str | None = None
    docker_image: str = "ghcr.io/bgp/bgpq4"

    @field_validator("asn")
    @classmethod
    def validate_asn(cls, v: str) -> str:
        normalized = v.upper()
        if not normalized.startswith("AS"):
            normalized = f"AS{normalized}"
        stripped = normalized[2:]
        if not stripped.isdigit():
            raise ValueError(f"Invalid ASN: {v}")
        return normalized


class CountryGeoliteSource(BaseModel):
    id: str
    type: Literal["country_geolite"] = "country_geolite"
    mmdb_path: str
    countries: list[str]  # ISO 3166-1 alpha-2

    @field_validator("countries")
    @classmethod
    def validate_countries(cls, v: list[str]) -> list[str]:
        return [c.upper() for c in v]


class CloudflareIpsSource(BaseModel):
    """Aggregated Cloudflare IP ranges (ips-v4 / ips-v6 endpoints)."""

    id: str
    type: Literal["cloudflare_ips"] = "cloudflare_ips"
    urls: list[str] = Field(
        default_factory=lambda: [
            "https://www.cloudflare.com/ips-v4/",
            "https://www.cloudflare.com/ips-v6/",
        ],
    )


class CloudflareLocalSource(BaseModel):
    """Cloudflare per-PoP IP allocations with country/city filtering.

    Fetches ``local-ip-ranges.csv`` (format: ``CIDR,country,region,city,``)
    and filters by ISO country codes and/or city names.
    """

    id: str
    type: Literal["cloudflare_local"] = "cloudflare_local"
    url: str = "https://api.cloudflare.com/local-ip-ranges.csv"
    countries: list[str] = Field(
        default_factory=list,
        description="ISO country codes to include. Empty = all.",
    )
    cities: list[str] = Field(
        default_factory=list,
        description="City names to include (case-insensitive). Empty = all.",
    )

    @field_validator("countries")
    @classmethod
    def normalize_countries(cls, v: list[str]) -> list[str]:
        return [c.upper() for c in v]

    @field_validator("cities")
    @classmethod
    def normalize_cities(cls, v: list[str]) -> list[str]:
        return [c.lower() for c in v]


SourceConfig = (
    X4bListSource
    | AsnBgpq4Source
    | CountryGeoliteSource
    | CloudflareIpsSource
    | CloudflareLocalSource
)


# ---------------------------------------------------------------------------
# Summarization bounds
# ---------------------------------------------------------------------------
class SummarizationConfig(BaseModel):
    enabled: bool = True
    max_expansion_ratio: float | None = None
    max_supernet_width: int | None = None
    max_prefix_loss_risk: float | None = None


# ---------------------------------------------------------------------------
# Target reference in policy
# ---------------------------------------------------------------------------
class TargetConfig(BaseModel):
    type: Literal["linode", "linode_interface", "nodebalancer"]
    id: int


# ---------------------------------------------------------------------------
# Single policy definition
# ---------------------------------------------------------------------------
class PolicyConfig(BaseModel):
    name: str
    firewall_label: str
    mode: Literal["allow", "deny"]
    source_ids: list[str]
    ip_families: list[Literal["ipv4", "ipv6"]] = Field(
        default_factory=lambda: ["ipv4", "ipv6"]
    )
    traffic_scope: Literal[
        "inbound_tcp_udp", "inbound_tcp", "inbound_udp", "inbound_all",
        "outbound_tcp_udp", "outbound_tcp", "outbound_udp", "outbound_all",
        "bidirectional_tcp_udp",
    ] = "inbound_tcp_udp"
    ports: str = Field(
        default="1-65535",
        description=(
            "Port specification for TCP/UDP rules. Supports single ports, "
            "comma-separated lists, and ranges. Examples: '22', '80, 443', "
            "'22, 80, 443, 8000-9000'. Max 15 entries per Linode rule. "
            "Ignored for ICMP protocol."
        ),
    )
    targets: list[TargetConfig] = Field(default_factory=list)
    summarization: SummarizationConfig = Field(default_factory=SummarizationConfig)
    tags: list[str] = Field(default_factory=lambda: ["lfw-managed"])

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        """Validate port specification against Linode limits."""
        if not v or not v.strip():
            return "1-65535"
        entries = [e.strip() for e in v.split(",") if e.strip()]
        if len(entries) > 15:
            raise ValueError(
                f"Too many port entries ({len(entries)}). "
                f"Linode allows max 15 ports/ranges per rule."
            )
        for entry in entries:
            if "-" in entry:
                parts = entry.split("-")
                if len(parts) != 2:
                    raise ValueError(f"Invalid port range: '{entry}'")
                low, high = int(parts[0]), int(parts[1])
                if not (1 <= low <= 65535 and 1 <= high <= 65535 and low <= high):
                    raise ValueError(f"Port range out of bounds: '{entry}'")
            else:
                port = int(entry)
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port out of range: {port}")
        return ", ".join(entries)

    @model_validator(mode="after")
    def validate_nodebalancer_scope(self) -> PolicyConfig:
        """NodeBalancer targets only support inbound TCP rules."""
        has_nb = any(t.type == "nodebalancer" for t in self.targets)
        outbound_scopes = {
            "outbound_tcp_udp", "outbound_tcp", "outbound_udp",
            "outbound_all", "bidirectional_tcp_udp",
        }
        if has_nb and self.traffic_scope in outbound_scopes:
            raise ValueError(
                f"NodeBalancer targets do not support scope '{self.traffic_scope}'. "
                "Use an inbound-only scope (e.g. 'inbound_tcp_udp' or 'inbound_tcp')."
            )
        return self


# ---------------------------------------------------------------------------
# Execution defaults
# ---------------------------------------------------------------------------
class ExecutionConfig(BaseModel):
    dry_run: bool = True
    parallelism: int = Field(default=1, ge=1, le=4)
    fail_on_warnings: bool = False


# ---------------------------------------------------------------------------
# Root policy spec
# ---------------------------------------------------------------------------
class PolicySpec(BaseModel):
    version: int = 1
    linode: LinodeSettings = Field(default_factory=LinodeSettings)
    sources: list[Annotated[SourceConfig, Field(discriminator="type")]]
    policies: list[PolicyConfig]
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)

    @model_validator(mode="after")
    def validate_source_refs(self) -> PolicySpec:
        """Ensure all source_ids in policies reference defined sources."""
        defined = {s.id for s in self.sources}
        for policy in self.policies:
            missing = set(policy.source_ids) - defined
            if missing:
                raise ValueError(
                    f"Policy '{policy.name}' references undefined sources: {missing}"
                )
        return self

    @model_validator(mode="after")
    def validate_unique_names(self) -> PolicySpec:
        """Ensure unique policy names and source IDs."""
        seen_policies: set[str] = set()
        for p in self.policies:
            if p.name in seen_policies:
                raise ValueError(f"Duplicate policy name: '{p.name}'")
            seen_policies.add(p.name)
        seen_sources: set[str] = set()
        for s in self.sources:
            if s.id in seen_sources:
                raise ValueError(f"Duplicate source id: '{s.id}'")
            seen_sources.add(s.id)
        return self


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
def load_policy_file(path: str | Path) -> PolicySpec:
    """Load and validate a policy YAML file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if not isinstance(raw, dict):
        raise ValueError(f"Policy file must be a YAML mapping, got {type(raw).__name__}")
    return PolicySpec.model_validate(raw)
