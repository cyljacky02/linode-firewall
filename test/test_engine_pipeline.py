"""Integration test: full engine pipeline without Linode API.

Exercises: source fetch → normalize → summarize → rule build → payload hash.
"""

from lfw.core.types import IpFamily, PolicyMode, SummarizationBounds, TrafficScope, canonical_rules_hash
from lfw.engine.normalizer import build_resolved_set, compute_packing_capacity
from lfw.engine.rule_builder import build_rule_pack, rule_packs_to_api_payload
from lfw.engine.summarizer import summarize_prefix_set
from lfw.schema.policy import load_policy_file
from lfw.sources.factory import create_provider


def test_x4b_full_pipeline():
    """Fetch X4B VPN list → normalize → summarize → build rules → verify payload."""
    spec = load_policy_file("examples/policy.yaml")

    # Locate X4B source and block-vpn policy
    source_cfg = next(s for s in spec.sources if s.id == "x4b-vpn")
    policy_cfg = next(p for p in spec.policies if p.name == "block-vpn")

    # Step 1: Fetch
    provider = create_provider(source_cfg)
    snapshot, records = provider.fetch()
    print(f"[1] Fetched: {snapshot.raw_count} raw, {snapshot.normalized_count} normalized")
    print(f"    SHA256: {snapshot.sha256[:16]}...")
    assert snapshot.normalized_count > 0, "Expected non-empty X4B list"

    # Step 2: Normalize
    families = [IpFamily(f) for f in policy_cfg.ip_families]
    prefix_set = build_resolved_set(
        policy_name=policy_cfg.name,
        records=records,
        ip_families=families,
        snapshot_refs=[snapshot.source_id],
    )
    print(f"[2] Normalized: {prefix_set.raw_count} raw → {prefix_set.normalized_count} collapsed")
    print(f"    IPv4: {len(prefix_set.ipv4_cidrs)}, IPv6: {len(prefix_set.ipv6_cidrs)}")
    assert prefix_set.normalized_count > 0

    # Step 3: Check capacity (protocol-aware: TCP+UDP = 2 protocols)
    protocol_count = 2  # inbound_tcp_udp → TCP + UDP
    capacity = compute_packing_capacity(protocol_count=protocol_count)
    effective_rules = 25 // protocol_count
    print(f"[3] Linode capacity: {capacity} CIDRs ({effective_rules} rules/proto × 255 addrs × {protocol_count} protos)")
    needs_summarization = prefix_set.normalized_count > capacity
    print(f"    Needs summarization: {needs_summarization}")

    # Step 4: Summarize
    mode = PolicyMode(policy_cfg.mode)
    overrides = SummarizationBounds(
        max_expansion_ratio=policy_cfg.summarization.max_expansion_ratio or 8.0,
        max_supernet_width=policy_cfg.summarization.max_supernet_width or 16,
        max_prefix_loss_risk=policy_cfg.summarization.max_prefix_loss_risk or 0.80,
    )
    ipv4_summarized, ipv6_summarized, reports = summarize_prefix_set(
        ipv4_cidrs=prefix_set.ipv4_cidrs,
        ipv6_cidrs=prefix_set.ipv6_cidrs,
        mode=mode,
        max_rules_for_policy=effective_rules,
        overrides=overrides,
    )
    print(f"[4] Summarized: {len(ipv4_summarized)} IPv4, {len(ipv6_summarized)} IPv6")
    for r in reports:
        print(f"    {r.family.value}: {r.input_count}→{r.output_count} "
              f"(ratio={r.expansion_ratio:.2f}, pass={r.passed})")
        print(f"    Detail: {r.detail}")

    # Step 5: Build rules
    scope = TrafficScope(policy_cfg.traffic_scope)
    rule_packs = build_rule_pack(
        ipv4_cidrs=ipv4_summarized,
        ipv6_cidrs=ipv6_summarized,
        mode=mode,
        traffic_scope=scope,
        policy_name=policy_cfg.name,
    )
    payload = rule_packs_to_api_payload(rule_packs)
    payload_hash = canonical_rules_hash(payload)

    inbound_rules = payload.get("inbound", [])
    outbound_rules = payload.get("outbound", [])
    total_rules = len(inbound_rules) + len(outbound_rules)
    total_v4 = sum(len(r["addresses"].get("ipv4", [])) for r in inbound_rules)
    total_v6 = sum(len(r["addresses"].get("ipv6", [])) for r in inbound_rules)

    print(f"[5] Rules built:")
    print(f"    Inbound: {len(inbound_rules)} rules (policy={payload['inbound_policy']})")
    print(f"    Outbound: {len(outbound_rules)} rules (policy={payload['outbound_policy']})")
    print(f"    Total CIDRs packed: {total_v4} IPv4 + {total_v6} IPv6")
    print(f"    Payload hash: {payload_hash[:16]}")

    # Assertions
    assert total_rules <= 25, f"Exceeded 25-rule limit: {total_rules}"
    for rule in inbound_rules:
        addrs = rule["addresses"]
        addr_count = len(addrs.get("ipv4", [])) + len(addrs.get("ipv6", []))
        assert addr_count <= 255, f"Rule '{rule['label']}' has {addr_count} addresses (>255)"
    assert payload["inbound_policy"] == "ACCEPT", "Deny mode should have ACCEPT baseline"

    # Step 6: Idempotency check — second run produces same hash
    payload2 = rule_packs_to_api_payload(
        build_rule_pack(ipv4_summarized, ipv6_summarized, mode, scope, policy_cfg.name)
    )
    hash2 = canonical_rules_hash(payload2)
    assert hash2 == payload_hash, f"Idempotency failed: {payload_hash} != {hash2}"
    print(f"[6] Idempotency: PASS (hash stable across runs)")

    print("\n=== ALL CHECKS PASSED ===")


if __name__ == "__main__":
    test_x4b_full_pipeline()
