"""SDK-first hybrid Linode adapter for firewall operations.

Uses linode_api4 for core object workflows and falls back to low-level
client.get/put/post for endpoint gaps (e.g. service-assignment replace).
"""

from __future__ import annotations

import logging

from linode_api4 import LinodeClient
from linode_api4.objects.networking import Firewall

from lfw.core.constants import DEFAULT_BASE_URL, DEFAULT_PAGE_SIZE, DEFAULT_RETRY_COUNT
from lfw.core.exceptions import (
    BetaUnavailableError,
    LinodeApiError,
)
from lfw.core.types import (
    ApplyPlan,
    ApplyResult,
    DeviceType,
    TargetRef,
    canonical_rules_hash,
)

logger = logging.getLogger(__name__)


class LinodeAdapter:
    """Manages all interactions with the Linode API."""

    def __init__(
        self,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        page_size: int = DEFAULT_PAGE_SIZE,
        retry_count: int = DEFAULT_RETRY_COUNT,
        beta_enabled: bool = False,
    ) -> None:
        effective_url = base_url
        if beta_enabled and "v4beta" not in base_url:
            effective_url = base_url.replace("/v4", "/v4beta")

        self._client = LinodeClient(token, base_url=effective_url)
        self._page_size = page_size
        self._retry_count = retry_count
        self._beta_enabled = beta_enabled

    # ------------------------------------------------------------------
    # Token scope verification
    # ------------------------------------------------------------------
    def verify_token_scopes(self) -> dict[str, str]:
        """Check token scopes via /profile/grants. Returns scope map."""
        try:
            resp = self._client.get("/profile")
            return {"username": resp.get("username", "unknown")}
        except Exception as exc:
            raise LinodeApiError(0, f"Token verification failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Firewall CRUD
    # ------------------------------------------------------------------
    def find_firewall_by_label(self, label: str) -> Firewall | None:
        """Find a firewall by exact label match using SDK filters."""
        firewalls = self._client.networking.firewalls(
            Firewall.label == label
        )
        for fw in firewalls:
            if fw.label == label:
                return fw
        return None

    def create_firewall(
        self,
        label: str,
        rules: dict,
        tags: list[str] | None = None,
    ) -> Firewall:
        """Create a new firewall with the given rules."""
        logger.info("Creating firewall: %s", label)
        fw = self._client.networking.firewall_create(
            label=label,
            rules=rules,
            tags=tags or [],
        )
        logger.info("Firewall created: id=%d label=%s", fw.id, fw.label)
        return fw

    def get_firewall_rules(self, firewall: Firewall) -> dict:
        """Read current rules from a firewall."""
        return firewall.get_rules()

    def update_firewall_rules(self, firewall: Firewall, rules: dict) -> None:
        """Full-replace firewall rules (PUT semantics)."""
        logger.info("Updating rules for firewall %d (%s)", firewall.id, firewall.label)
        firewall.update_rules(rules)

    # ------------------------------------------------------------------
    # Device attachment
    # ------------------------------------------------------------------
    def get_firewall_devices(self, firewall: Firewall) -> list[dict]:
        """List current devices attached to a firewall."""
        devices = []
        for device in firewall.devices:
            devices.append({
                "id": device.id,
                "type": getattr(device, "type", "linode"),
                "entity_id": getattr(getattr(device, "entity", None), "id", None),
            })
        return devices

    def attach_device(
        self,
        firewall: Firewall,
        target: TargetRef,
    ) -> None:
        """Attach a device to the firewall. Idempotent — skips if already attached."""
        existing = self.get_firewall_devices(firewall)
        for dev in existing:
            if dev.get("entity_id") == target.identifier:
                logger.debug(
                    "Device %s/%s already attached to firewall %d",
                    target.device_type.value,
                    target.identifier,
                    firewall.id,
                )
                return

        logger.info(
            "Attaching %s %s to firewall %d",
            target.device_type.value,
            target.identifier,
            firewall.id,
        )

        if target.device_type == DeviceType.LINODE:
            firewall.device_create(int(target.identifier), "linode")
        elif target.device_type == DeviceType.NODEBALANCER:
            firewall.device_create(int(target.identifier), "nodebalancer")
        elif target.device_type == DeviceType.LINODE_INTERFACE:
            # SDK may not have direct support; use low-level PUT
            self._client.post(
                f"/networking/firewalls/{firewall.id}/devices",
                data={"type": "linode_interface", "id": int(target.identifier)},
            )

    def detach_device(self, firewall: Firewall, device_id: int) -> None:
        """Remove a device from the firewall."""
        logger.info("Detaching device %d from firewall %d", device_id, firewall.id)
        self._client.delete(f"/networking/firewalls/{firewall.id}/devices/{device_id}")

    # ------------------------------------------------------------------
    # Beta: templates and default settings
    # ------------------------------------------------------------------
    def get_firewall_templates(self) -> list[dict] | None:
        """Fetch firewall templates (beta). Returns None if unavailable."""
        if not self._beta_enabled:
            return None
        try:
            resp = self._client.get("/networking/firewalls/templates")
            return resp.get("data", [])
        except Exception as exc:
            logger.warning("Beta firewall templates unavailable: %s", exc)
            return None

    def get_default_firewall_settings(self) -> dict | None:
        """Read account default firewall settings (beta)."""
        if not self._beta_enabled:
            return None
        try:
            resp = self._client.get("/networking/firewalls/settings")
            return resp
        except Exception as exc:
            logger.warning("Beta default firewall settings unavailable: %s", exc)
            return None

    def update_default_firewall_settings(self, settings: dict) -> dict | None:
        """Write account default firewall settings (beta)."""
        if not self._beta_enabled:
            raise BetaUnavailableError(
                "Beta features not enabled. Set beta_enabled: true in policy."
            )
        try:
            return self._client.put("/networking/firewalls/settings", data=settings)
        except Exception as exc:
            status = getattr(exc, "status", 0)
            if status in (403, 404):
                raise BetaUnavailableError(
                    f"Default firewall settings endpoint unavailable: {exc}"
                ) from exc
            raise

    # ------------------------------------------------------------------
    # Inspect
    # ------------------------------------------------------------------
    def inspect_firewall(self, label: str) -> dict | None:
        """Full inspection of a firewall: rules, devices, version info."""
        fw = self.find_firewall_by_label(label)
        if fw is None:
            return None

        rules = self.get_firewall_rules(fw)
        devices = self.get_firewall_devices(fw)

        return {
            "id": fw.id,
            "label": fw.label,
            "status": fw.status,
            "tags": list(fw.tags),
            "created": str(fw.created),
            "updated": str(fw.updated),
            "rules": rules,
            "rules_hash": canonical_rules_hash(rules),
            "devices": devices,
            "device_count": len(devices),
        }

    # ------------------------------------------------------------------
    # Apply plan execution
    # ------------------------------------------------------------------
    def execute_plan(self, plan: ApplyPlan) -> ApplyResult:
        """Execute an apply plan with actual API mutations."""
        actions: list[str] = []
        errors: list[str] = []

        try:
            # Create or find firewall
            if plan.create_firewall:
                fw = self.create_firewall(
                    label=plan.firewall_label,
                    rules=plan.desired_payload,
                )
                plan.firewall_id = fw.id
                actions.append(f"Created firewall '{plan.firewall_label}' (id={fw.id})")
            else:
                fw = self.find_firewall_by_label(plan.firewall_label)
                if fw is None:
                    errors.append(
                        f"Firewall '{plan.firewall_label}' not found for update"
                    )
                    return ApplyResult(
                        policy_name=plan.policy_name,
                        success=False,
                        errors=errors,
                    )

                # Update rules if changed
                if plan.rules_changed:
                    self.update_firewall_rules(fw, plan.desired_payload)
                    actions.append(
                        f"Updated rules on firewall '{plan.firewall_label}' "
                        f"(hash: {plan.current_rules_hash[:8]}→{plan.desired_rules_hash[:8]})"
                    )
                else:
                    actions.append("Rules unchanged (no-op)")

            # Attach devices
            for target in plan.attachments_to_add:
                try:
                    self.attach_device(fw, target)
                    actions.append(
                        f"Attached {target.device_type.value} {target.identifier}"
                    )
                except Exception as exc:
                    errors.append(
                        f"Failed to attach {target.device_type.value} "
                        f"{target.identifier}: {exc}"
                    )

            # Detach devices
            for target in plan.attachments_to_remove:
                try:
                    self.detach_device(fw, int(target.identifier))
                    actions.append(
                        f"Detached device {target.identifier}"
                    )
                except Exception as exc:
                    errors.append(f"Failed to detach device {target.identifier}: {exc}")

        except Exception as exc:
            errors.append(f"Unexpected error: {exc}")

        return ApplyResult(
            policy_name=plan.policy_name,
            success=len(errors) == 0,
            firewall_id=plan.firewall_id,
            actions_taken=actions,
            errors=errors,
        )
