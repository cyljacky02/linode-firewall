"""Schema validation edge cases — ensures Pydantic catches all invalid inputs."""

import pytest
from pydantic import ValidationError

from lfw.schema.policy import PolicySpec, load_policy_file


def _base_spec(**overrides) -> dict:
    """Minimal valid spec dict for patching."""
    base = {
        "version": 1,
        "sources": [{"id": "s1", "type": "x4b_list"}],
        "policies": [
            {
                "name": "p1",
                "firewall_label": "fw1",
                "mode": "deny",
                "source_ids": ["s1"],
            }
        ],
    }
    base.update(overrides)
    return base


def test_valid_minimal():
    spec = PolicySpec.model_validate(_base_spec())
    assert len(spec.sources) == 1
    assert len(spec.policies) == 1
    print("  valid_minimal: PASS")


def test_missing_source_ref():
    data = _base_spec()
    data["policies"][0]["source_ids"] = ["nonexistent"]
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError as e:
        assert "undefined sources" in str(e).lower() or "nonexistent" in str(e)
        print("  missing_source_ref: PASS")


def test_duplicate_policy_names():
    data = _base_spec()
    data["policies"].append({
        "name": "p1",  # duplicate
        "firewall_label": "fw2",
        "mode": "allow",
        "source_ids": ["s1"],
    })
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError as e:
        assert "duplicate" in str(e).lower()
        print("  duplicate_policy_names: PASS")


def test_duplicate_source_ids():
    data = _base_spec()
    data["sources"].append({"id": "s1", "type": "x4b_list"})  # duplicate
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError as e:
        assert "duplicate" in str(e).lower()
        print("  duplicate_source_ids: PASS")


def test_invalid_asn():
    data = _base_spec()
    data["sources"] = [{"id": "bad", "type": "asn_bgpq4", "asn": "NOTANASN"}]
    data["policies"][0]["source_ids"] = ["bad"]
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError as e:
        assert "asn" in str(e).lower() or "invalid" in str(e).lower()
        print("  invalid_asn: PASS")


def test_valid_asn_normalization():
    data = _base_spec()
    data["sources"] = [{"id": "a1", "type": "asn_bgpq4", "asn": "3462"}]
    data["policies"][0]["source_ids"] = ["a1"]
    spec = PolicySpec.model_validate(data)
    assert spec.sources[0].asn == "AS3462"  # type: ignore
    print("  valid_asn_normalization: PASS")


def test_nodebalancer_outbound_rejected():
    data = _base_spec()
    data["policies"][0]["traffic_scope"] = "outbound_tcp_udp"
    data["policies"][0]["targets"] = [{"type": "nodebalancer", "id": 123}]
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError as e:
        assert "nodebalancer" in str(e).lower()
        print("  nodebalancer_outbound_rejected: PASS")


def test_invalid_mode():
    data = _base_spec()
    data["policies"][0]["mode"] = "block"  # invalid, must be allow/deny
    try:
        PolicySpec.model_validate(data)
        assert False, "Should have raised"
    except ValidationError:
        print("  invalid_mode: PASS")


def test_missing_policy_file():
    try:
        load_policy_file("nonexistent.yaml")
        assert False, "Should have raised"
    except FileNotFoundError:
        print("  missing_policy_file: PASS")


if __name__ == "__main__":
    print("Schema edge-case tests:")
    test_valid_minimal()
    test_missing_source_ref()
    test_duplicate_policy_names()
    test_duplicate_source_ids()
    test_invalid_asn()
    test_valid_asn_normalization()
    test_nodebalancer_outbound_rejected()
    test_invalid_mode()
    test_missing_policy_file()
    print("\n=== ALL SCHEMA TESTS PASSED ===")
