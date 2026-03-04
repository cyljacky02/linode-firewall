# Linode Firewall Policy Engine (Python, CLI-first, SDK-hybrid)

## Summary
As of **March 4, 2026**, this plan designs a greenfield Python project that reconciles external IP intelligence into Linode Cloud Firewalls with reproducible state and safe automation.

1. Build a **CLI-first firewall policy engine** that supports your three scenarios: block `X4BNet/lists_vpn`, allow ASN-derived prefixes (for example `AS3462`), and allow country-derived prefixes (for example Taiwan).
2. Use a **SDK-first hybrid adapter**: `linode_api4` for core object workflows plus direct REST calls through the SDK client where wrappers are missing.
3. Persist run/source/apply metadata in **SQLite**.
4. Implement **auto-summarization with bounded expansion** (your selected mode), including hard guardrails and explicit fit/fail diagnostics for Linode capacity limits.
5. Include **full beta support** for firewall templates and default firewall settings, with graceful capability detection.

## Public Interfaces and Types

### CLI Surface
1. `lfw policy validate --file <policy.yaml>` validates schema, source availability, and fit simulation.
2. `lfw policy plan --file <policy.yaml> [--policy <name>]` resolves sources, summarizes prefixes, computes Linode diffs, and outputs a non-mutating plan.
3. `lfw policy apply --file <policy.yaml> [--policy <name>]` executes the same plan with writes enabled and records audit history.
4. `lfw source refresh --source <id|all>` refreshes raw source snapshots into SQLite cache.
5. `lfw inspect firewall --label <label>` shows current rules, version/fingerprint, devices, and drift versus last planned state.

### Policy Spec (YAML)
1. `version` integer for schema migration.
2. `linode` object with `base_url`, `page_size`, `retry`, and `beta_enabled`.
3. `sources` array with typed sources: `x4b_list`, `asn_bgpq4`, `country_geolite`.
4. `policies` array with `name`, `firewall_label`, `mode` (`allow` or `deny`), `targets`, `ip_families`, `traffic_scope`, `summarization`, and optional tags.
5. `execution` object with defaults for `dry_run`, `parallelism`, and `fail_on_warnings`.

### Core Python Types
1. `SourceSnapshot`, `ResolvedPrefixSet`, `SummarizationReport`, `RulePack`, `ApplyPlan`, and `ApplyResult` dataclasses.
2. `TargetRef` union type for `linode`, `linode_interface`, and `nodebalancer`.
3. `SummarizationPolicy` with explicit numeric bounds per mode and family.

## Implementation Design

### 1) Source Ingestion
1. `x4b_list` fetches `output/vpn/ipv4.txt` and optionally other configured list paths, parses one CIDR per line, and stores immutable snapshot metadata (`sha256`, URL, fetched time).
2. `asn_bgpq4` executes `bgpq4` in this order: local binary detect, Docker image fallback, explicit failure with install guidance if neither path works.
3. `country_geolite` ingests GeoLite `.mmdb` and performs deterministic country extraction by iterating record networks (not brute force address iteration), producing country prefix sets by family.
4. Every source writes `raw_count`, `normalized_count`, and freshness fields to SQLite.

### 2) Normalization and Pre-fit Checks
1. Normalize CIDRs with strict parsing and canonical network form.
2. De-duplicate exact entries and do exact collapses.
3. Track provenance per prefix (`source_id`, `country`, `asn`, or list path) for explainability.
4. Perform fit pre-check against Linode packing model before API mutations.

### 3) Summarization Engine (Bounded Expansion)
1. If normalized set exceeds rule packing capacity, run hierarchical supernet merge with explicit guardrails.
2. Guardrails are configurable and enforced per policy/family: `max_expansion_ratio`, `max_supernet_width`, and `max_prefix_loss_risk`.
3. Default guardrails: stricter for `allow` mode than `deny` mode; both are overrideable per policy.
4. Output full summarization report with `input_count`, `output_count`, `expansion_ratio`, largest supernet applied, and dropped/retained rationale.
5. If limits still cannot be met under bounds, fail with remediation options and without partial writes.

### 4) Rule Builder
1. Default traffic scope is your selected `inbound_tcp_udp`.
2. Allowlist baseline is your selected `inbound_policy=DROP`, with generated `ACCEPT` rules for matched prefixes.
3. Denylist baseline defaults to `inbound_policy=ACCEPT`, with generated `DROP` rules for matched prefixes.
4. NodeBalancer-targeted policies auto-enforce API semantics by generating inbound TCP-only rule packs.
5. Rule order is deterministic and stable, with canonical JSON output for accurate no-op detection.

### 5) Linode Adapter (SDK-first Hybrid)
1. Use `linode_api4` for firewall listing/creation, rule read/write, history/rule-versions, device create/delete, templates, and settings objects.
2. Use low-level `client.put(...)` for endpoint gaps in high-level wrappers, especially service-assignment replace flows where needed.
3. Use `page_size` control for collection calls and optional SDK filter expressions for label-based lookups.
4. Reconcile by diff: canonical desired rules versus current rules payload, plus fingerprint/version awareness.
5. Respect API replacement semantics: `PUT /firewalls/{id}/rules` is full replacement, so every apply sends complete intended rule state.

### 6) Target Attachment Strategy (Firewall-centric)
1. Primary unit is a managed firewall object identified by label plus management tags.
2. Optional explicit `targets` in policy drive attachments to `linode`, `linode_interface`, and `nodebalancer`.
3. Attachment reconciliation is diff-based with idempotent add/remove behavior.
4. Policy engine prevents unsupported combinations and surfaces actionable errors.

### 7) Beta Features (Full Support)
1. Read/write default firewall settings endpoints when account capability allows.
2. Read firewall templates (`vpc`, `public`) and allow policy bootstrap from template rules.
3. Capability detection: on 403/404 beta unavailability, fail or warn according to policy strictness.

### 8) State and Audit (SQLite)
1. Tables: `source_snapshots`, `prefixes`, `policy_runs`, `summaries`, `plans`, `apply_actions`, `linode_observed_state`.
2. Each run stores exact input snapshot references and exact output rule payload hash.
3. Every mutation stores before/after artifacts for audit and rollback planning.
4. Optional export command writes human-readable run report (JSON/Markdown).

## Linode Alignment and Best-Practice Controls
1. Enforce least-privilege token usage with clear scope checks before apply.
2. Handle rate-limits using SDK retry behavior and respect `Retry-After`.
3. Keep collection calls paginated and bounded by configurable `page_size`.
4. Make all operations idempotent, deterministic, and explicit about full-replace endpoints.
5. Treat migration-related API failures as retriable only when semantically safe; otherwise fail fast with diagnostics.

## Test Plan and Acceptance Scenarios

### Unit Tests
1. CIDR parser and canonicalizer with malformed/edge input.
2. GeoLite country extraction correctness on fixture MMDB.
3. `bgpq4` output parsing and fallback execution path selection.
4. Summarization bound enforcement and deterministic output ordering.
5. Rule packing math versus Linode constraints, including NodeBalancer-specific behavior.

### Integration Tests (Mocked Linode API)
1. Firewall create/update/no-op reconciliation and canonical diff behavior.
2. Rule replacement semantics and idempotent repeated apply.
3. Attachment add/remove reconciliation across all target types.
4. Retry and 429 handling with `Retry-After`.
5. Beta endpoint success and beta unavailability fallback paths.

### Scenario Tests (Your examples)
1. **Block X4B VPN list**: engine fetches list, summarizes under configured bounds, generates inbound TCP/UDP deny rules, and applies.
2. **Allow AS3462**: engine resolves ASN prefixes via `bgpq4`, sets inbound baseline DROP, generates allow rules, and applies.
3. **Allow Taiwan**: engine extracts country prefixes from GeoLite source, applies allowlist policy with bounded summarization.
4. Each scenario must pass dry-run plan first and produce stable second-run no-op result.

## Rollout and Operations
1. Phase 1: implement `validate` and `plan` only, with no write paths.
2. Phase 2: enable `apply` with explicit confirmation and full audit logging.
3. Phase 3: add scheduled execution guidance for Windows Task Scheduler (not default runtime mode).
4. Operational outputs include run summary, risk metrics, and exact API actions taken.

## Assumptions and Defaults Chosen
1. Runtime is Python under Miniforge; token provided via `LINODE_TOKEN` and optional `.env`.
2. Default Linode API base URL is `https://api.linode.com/v4`.
3. SDK package target is current stable line (`linode-api4`), with hybrid REST fallback where wrappers are incomplete.
4. Default family mode is dual-stack where source data exists; absent family data is treated explicitly, not silently inferred.
5. Auto-summarization is enabled but bounded; if a policy cannot fit within bounds, apply fails with remediation instructions.
6. Dry-run is the default command behavior unless `apply` is explicitly invoked.

## References Used
1. Linode OpenAPI (development): `https://raw.githubusercontent.com/linode/linode-api-docs/refs/heads/development/openapi.json`
2. Linode API docs repo and releases: `https://github.com/linode/linode-api-docs`
3. Linode API pagination/rate limit/filtering docs:  
   `https://techdocs.akamai.com/linode-api/reference/pagination`  
   `https://techdocs.akamai.com/linode-api/reference/rate-limits`  
   `https://techdocs.akamai.com/linode-api/reference/filtering-and-sorting`
4. `linode_api4-python` repo and latest release data:  
   `https://github.com/linode/linode_api4-python`  
   `https://github.com/linode/linode_api4-python/releases`
5. `linode_api4-python` source files inspected:  
   `https://raw.githubusercontent.com/linode/linode_api4-python/dev/linode_api4/linode_client.py`  
   `https://raw.githubusercontent.com/linode/linode_api4-python/dev/linode_api4/groups/networking.py`  
   `https://raw.githubusercontent.com/linode/linode_api4-python/dev/linode_api4/objects/networking.py`
6. `bgpq4` README and repo metadata:  
   `https://github.com/bgp/bgpq4`  
   `https://raw.githubusercontent.com/bgp/bgpq4/main/README.md`
7. `X4BNet/lists_vpn` README and list paths:  
   `https://github.com/X4BNet/lists_vpn`  
   `https://raw.githubusercontent.com/X4BNet/lists_vpn/main/README.md`
8. `P3TERX/GeoLite.mmdb` README and repo metadata:  
   `https://github.com/P3TERX/GeoLite.mmdb`  
   `https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/main/README.md`
