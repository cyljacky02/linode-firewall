# lfw — Linode Firewall Policy Engine

A CLI-first, SDK-hybrid firewall policy engine that reconciles external IP intelligence into [Linode Cloud Firewalls](https://www.linode.com/products/cloud-firewall/) with reproducible state, bounded summarization, and safe automation.

## Features

- **4 IP source types** — X4BNet VPN lists, ASN prefixes (bgpq4), GeoLite2 country extraction, Cloudflare IP ranges
- **9 traffic scopes** — `inbound_tcp`, `inbound_udp`, `inbound_tcp_udp`, `inbound_all`, `outbound_*`, `bidirectional_tcp_udp`
- **Bounded summarization** — Hierarchical supernet merging with configurable guardrails (`max_expansion_ratio`, `max_supernet_width`, `max_prefix_loss_risk`)
- **Multi-policy firewall merging** — Multiple policies can target the same firewall label; rules are merged into a single payload
- **Policy-level port configuration** — Per-policy port specs (e.g. `"22, 80, 443, 8000-9000"`)
- **Idempotent applies** — Canonical hash-based no-op detection with full PUT-replace semantics
- **SQLite audit trail** — Every run, plan, and mutation is recorded with before/after artifacts
- **SDK-hybrid adapter** — `linode_api4` for core workflows + low-level REST for endpoint gaps
- **Beta support** — Firewall templates and default settings with graceful 403/404 fallback

## Quick Start

### Install

```bash
python -m venv .venv
.venv/Scripts/activate   # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```

### Configure

```bash
cp .env.example .env
# Edit .env and set LINODE_TOKEN=your_token_here
```

### Usage

```bash
# Validate policy schema
lfw policy validate -f examples/policy.yaml

# Refresh source data into SQLite cache
lfw source refresh -f examples/policy.yaml

# Dry-run plan (non-mutating)
lfw policy plan -f examples/policy.yaml

# Plan a specific policy
lfw policy plan -f examples/policy.yaml -p block-vpn

# Apply (creates/updates firewalls)
lfw policy apply -f examples/policy.yaml --yes

# Inspect a firewall's current state and drift
lfw inspect firewall -l lfw-block-vpn
```

## Policy YAML

```yaml
version: 1

linode:
  base_url: "https://api.linode.com/v4"
  page_size: 100
  retry: 3
  beta_enabled: false

sources:
  - id: x4b-vpn
    type: x4b_list
    list_paths: ["output/vpn/ipv4.txt"]

  - id: cloudflare
    type: cloudflare_ips
    urls:
      - "https://www.cloudflare.com/ips-v4/"
      - "https://www.cloudflare.com/ips-v6/"

  - id: hinet
    type: asn_bgpq4
    asn: "AS3462"

  # - id: tw-geo
  #   type: country_geolite
  #   mmdb_path: "./GeoLite2-Country.mmdb"
  #   countries: ["TW"]

policies:
  - name: block-vpn
    firewall_label: my-fw
    mode: deny
    source_ids: [x4b-vpn]
    ip_families: [ipv4]
    traffic_scope: inbound_tcp_udp
    ports: "1-65535"
    summarization:
      enabled: true
      max_expansion_ratio: 8.0
      max_supernet_width: 16

  - name: allow-cf-ssh
    firewall_label: my-fw          # same firewall → merged
    mode: allow
    source_ids: [cloudflare]
    ip_families: [ipv4, ipv6]
    traffic_scope: inbound_tcp
    ports: "22, 80, 443"

execution:
  dry_run: true
  fail_on_warnings: false
```

## Source Types

| Type | Description | Config |
|---|---|---|
| `x4b_list` | [X4BNet](https://github.com/X4BNet/lists_vpn) VPN/datacenter IP lists | `list_paths`, `base_url` |
| `asn_bgpq4` | ASN prefix resolution via [bgpq4](https://github.com/bgp/bgpq4) | `asn`, `bgpq4_path`, `docker_image` |
| `country_geolite` | Country-level CIDR extraction from [GeoLite2](https://github.com/P3TERX/GeoLite.mmdb) MMDB | `mmdb_path`, `countries` |
| `cloudflare_ips` | [Cloudflare](https://www.cloudflare.com/ips/) aggregated IP ranges (~22 CIDRs) | `urls` |
| `cloudflare_local` | Cloudflare per-PoP IP allocations with country/city filtering | `url`, `countries`, `cities` |

### Cloudflare Source Types

**`cloudflare_ips`** — Aggregated IP ranges from `ips-v4` / `ips-v6` endpoints (~22 CIDRs). **Recommended** for firewall rules — fits easily within Linode limits.

**`cloudflare_local`** — Per-PoP IP allocations from `local-ip-ranges.csv` (~135K CIDRs). Supports filtering by ISO country code and/or city name:

```yaml
# All Cloudflare PoPs in Taiwan and Hong Kong
- id: cloudflare-tw
  type: cloudflare_local
  countries: ["TW", "HK"]

# Only Tokyo and Osaka PoPs
- id: cloudflare-tokyo
  type: cloudflare_local
  cities: ["tokyo", "osaka"]
```

Without filters, all ~135K CIDRs are returned (requires aggressive summarization). With country filtering, typical results are 300-500 CIDRs per country.

## Traffic Scopes

| Scope | Direction | Protocols | Rule Multiplier |
|---|---|---|---|
| `inbound_tcp_udp` | Inbound | TCP + UDP | ×2 |
| `inbound_tcp` | Inbound | TCP | ×1 |
| `inbound_udp` | Inbound | UDP | ×1 |
| `inbound_all` | Inbound | TCP + UDP + ICMP | ×3 |
| `outbound_tcp_udp` | Outbound | TCP + UDP | ×2 |
| `outbound_tcp` | Outbound | TCP | ×1 |
| `outbound_udp` | Outbound | UDP | ×1 |
| `outbound_all` | Outbound | TCP + UDP + ICMP | ×3 |
| `bidirectional_tcp_udp` | Both | TCP + UDP | ×4 |

## Linode Limits

- **25 rules** per firewall (inbound + outbound combined)
- **255 IP addresses** per rule
- **15 ports/ranges** per rule
- A service (Linode/NodeBalancer) can only be attached to **one firewall** at a time

## Architecture

```
src/lfw/
├── cli/          # Click CLI commands (policy, source, inspect)
├── core/         # Types, constants, exceptions
├── schema/       # Pydantic policy YAML validation
├── sources/      # Source providers (X4B, bgpq4, GeoLite, Cloudflare)
├── engine/       # Normalizer, summarizer, rule builder, planner
├── adapter/      # Linode SDK-hybrid API adapter
└── state/        # SQLite audit/state persistence
```

## Requirements

- Python ≥ 3.11
- `LINODE_TOKEN` environment variable or `.env` file
- [bgpq4](https://github.com/bgp/bgpq4) (optional, for ASN sources — Docker fallback supported)
- [GeoLite2-Country.mmdb](https://github.com/P3TERX/GeoLite.mmdb) (optional, for country sources)

## License

[MIT](LICENSE)
