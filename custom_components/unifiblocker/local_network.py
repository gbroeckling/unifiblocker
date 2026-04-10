"""Local-only network manager.

Manages the 192.168.2.x subnet for devices that should work locally
but have no internet access.  Handles:
  - IP range assignment by device category
  - Auto-picking the next available IP
  - DHCP reservation creation via UniFi API
  - Firewall rule management (block 192.168.2.0/24 from WAN)
  - Persistent tracking of assignments
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

STORAGE_KEY = "unifiblocker_localnet"
STORAGE_VERSION = 1

# ── Subnet configuration ─────────────────────────────────────────────

LOCAL_SUBNET = "192.168.2"
LOCAL_CIDR = "192.168.2.0/24"

# Firewall rule name managed by UniFi Blocker.
FIREWALL_RULE_NAME = "UniFi Blocker - Block Local-Only from WAN"

# ── IP range assignments by category ─────────────────────────────────
# Each tuple is (start, end) inclusive.

CATEGORY_RANGES: dict[str, tuple[int, int]] = {
    "camera":        (30, 50),
    "esphome":       (51, 70),
    "led":           (71, 90),
    "smart_speaker": (91, 100),
    "iot":           (101, 120),
    "streaming":     (121, 130),
    "printer":       (131, 140),
    "gaming":        (141, 150),
    "crypto":        (151, 160),
    "nas":           (161, 170),
    "ha_device":     (171, 180),
    "networking":    (181, 190),
    "computer":      (191, 210),
    "phone":         (211, 220),
    "tablet":        (221, 230),
}

# Catch-all for categories not listed above.
DEFAULT_RANGE = (231, 250)

# Reserved — never auto-assign.
RESERVED = {1, 2, 3, 4, 5, 255}


class LocalNetworkManager:
    """Manage 192.168.2.x assignments and the WAN-block firewall rule."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._assignments: dict[str, dict[str, Any]] = {}
        self._firewall_rule_id: str | None = None
        self._config: dict[str, Any] = {}

    # ── Persistence ──────────────────────────────────────────────────

    async def async_load(self) -> None:
        data = await self._store.async_load()
        if data and isinstance(data, dict):
            self._assignments = data.get("assignments", {})
            self._firewall_rule_id = data.get("firewall_rule_id")
            # Load user-customized config (subnet, ranges) if present.
            self._config = data.get("config", {})
        _LOGGER.debug("Local-net: loaded %d assignments", len(self._assignments))

    async def async_save(self) -> None:
        await self._store.async_save({
            "assignments": self._assignments,
            "firewall_rule_id": self._firewall_rule_id,
            "config": self._config,
        })

    # ── Config (user-customizable, defaults to constants above) ──────

    @property
    def subnet(self) -> str:
        return self._config.get("subnet", LOCAL_SUBNET)

    @property
    def cidr(self) -> str:
        return self._config.get("cidr", LOCAL_CIDR)

    @property
    def category_ranges(self) -> dict[str, tuple[int, int]]:
        custom = self._config.get("ranges")
        if custom:
            return {k: tuple(v) for k, v in custom.items()}
        return CATEGORY_RANGES

    async def update_config(
        self, subnet: str | None = None, cidr: str | None = None,
        ranges: dict | None = None
    ) -> None:
        """Update user-configurable network settings."""
        if subnet is not None:
            self._config["subnet"] = subnet
        if cidr is not None:
            self._config["cidr"] = cidr
        if ranges is not None:
            self._config["ranges"] = ranges
        await self.async_save()

    # ── Queries ──────────────────────────────────────────────────────

    @property
    def assignments(self) -> dict[str, dict[str, Any]]:
        return self._assignments

    @property
    def firewall_rule_id(self) -> str | None:
        return self._firewall_rule_id

    def get_assignment(self, mac: str) -> dict[str, Any] | None:
        return self._assignments.get(mac.lower())

    def used_ips(self) -> set[int]:
        """Return all last-octets currently assigned."""
        ips = set()
        for info in self._assignments.values():
            ip = info.get("ip", "")
            if ip.startswith(self.subnet + "."):
                try:
                    ips.add(int(ip.split(".")[-1]))
                except ValueError:
                    pass
        return ips

    def next_available_ip(self, category: str) -> str | None:
        """Pick the next free IP in the category's range.

        Waterfall strategy — never returns None until ALL 254 addresses
        are exhausted:
          1. Try the category's own range first
          2. Try the overflow/default range
          3. Steal from other category ranges that have free slots
             (least-used ranges first)
          4. Sweep the entire .1-.254 space for anything still free
        """
        used = self.used_ips() | RESERVED
        cat_ranges = self.category_ranges
        own_start, own_end = cat_ranges.get(category, DEFAULT_RANGE)

        # 1. Own category range.
        for octet in range(own_start, own_end + 1):
            if octet not in used:
                return f"{self.subnet}.{octet}"

        # 2. Default / overflow range.
        if (own_start, own_end) != DEFAULT_RANGE:
            ds, de = DEFAULT_RANGE
            for octet in range(ds, de + 1):
                if octet not in used:
                    return f"{self.subnet}.{octet}"

        # 3. Steal from other ranges, least-used first.
        other_ranges = [
            (cat, s, e) for cat, (s, e) in cat_ranges.items()
            if (s, e) != (own_start, own_end)
        ]
        # Sort by how many free slots each range has (most free first).
        other_ranges.sort(
            key=lambda r: -sum(1 for o in range(r[1], r[2] + 1) if o not in used)
        )
        for _cat, s, e in other_ranges:
            for octet in range(s, e + 1):
                if octet not in used:
                    _LOGGER.info(
                        "Category %s full, borrowing .%d from %s range",
                        category, octet, _cat,
                    )
                    return f"{self.subnet}.{octet}"

        # 4. Full sweep — anything from .1 to .254 that's still free.
        for octet in range(1, 255):
            if octet not in used:
                _LOGGER.info(
                    "All ranges full, using last-resort .%d for %s",
                    octet, category,
                )
                return f"{self.subnet}.{octet}"

        _LOGGER.error("All 254 addresses in %s.x are exhausted", self.subnet)
        return None

    def get_range_info(self) -> list[dict[str, Any]]:
        """Return IP range info for dashboard display."""
        used = self.used_ips()
        ranges = []
        for cat, (start, end) in sorted(self.category_ranges.items(), key=lambda x: x[1][0]):
            total = end - start + 1
            used_in_range = len([o for o in range(start, end + 1) if o in used])
            ranges.append({
                "category": cat,
                "range": f"{self.subnet}.{start}-{end}",
                "total": total,
                "used": used_in_range,
                "available": total - used_in_range,
            })
        return ranges

    # ── Actions ──────────────────────────────────────────────────────

    async def assign_local_ip(
        self,
        api: Any,
        mac: str,
        category: str,
        name: str = "",
    ) -> dict[str, Any]:
        """Assign a local-only IP to a device.

        1. Pick next available IP in the category range
        2. Find the UniFi user record for the MAC
        3. Set a DHCP reservation via the API
        4. Store the assignment locally
        """
        mac = mac.lower()

        # Check if already assigned.
        existing = self._assignments.get(mac)
        if existing:
            return {"ok": True, "ip": existing["ip"], "already_assigned": True}

        ip = self.next_available_ip(category)
        if not ip:
            return {"ok": False, "error": "No available IPs in range"}

        # Find the UniFi user record.
        user = await api.get_user_by_mac(mac)
        if not user:
            return {"ok": False, "error": f"MAC {mac} not found on controller"}

        user_id = user.get("_id", "")
        if not user_id:
            return {"ok": False, "error": "User record has no ID"}

        # Set the DHCP reservation.
        try:
            await api.set_fixed_ip(user_id, ip)
        except Exception as err:
            return {"ok": False, "error": f"Failed to set reservation: {err}"}

        # Block internet for this device via v2 Traffic Rule.
        block_result = await self.block_device_internet(api, mac)
        rule_id = block_result.get("rule_id", "")

        # Store locally.
        self._assignments[mac] = {
            "ip": ip,
            "category": category,
            "name": name,
            "user_id": user_id,
            "traffic_rule_id": rule_id,
        }
        await self.async_save()

        _LOGGER.info("Assigned %s → %s (category: %s, internet blocked: %s)",
                      mac, ip, category, block_result.get("ok", False))
        return {"ok": True, "ip": ip, "mac": mac, "category": category,
                "internet_blocked": block_result.get("ok", False),
                "block_error": block_result.get("error", "")}

    async def remove_assignment(self, api: Any, mac: str) -> dict[str, Any]:
        """Remove a local-only IP assignment and clear the reservation."""
        mac = mac.lower()
        info = self._assignments.get(mac)
        if not info:
            return {"ok": False, "error": "Not assigned"}

        user_id = info.get("user_id", "")
        if user_id:
            try:
                await api.clear_fixed_ip(user_id)
            except Exception as err:
                _LOGGER.warning("Could not clear reservation for %s: %s", mac, err)

        # Remove internet block.
        await self.unblock_device_internet(api, mac)

        self._assignments.pop(mac, None)
        await self.async_save()
        return {"ok": True, "mac": mac}

    # ── Firewall rule ────────────────────────────────────────────────
    #
    # Tries v2 Traffic Rules API first (newer UCG Max firmware), then
    # falls back to legacy firewall rules API. Only ever creates a
    # rule that blocks 192.168.2.0/24 from reaching the internet.

    async def ensure_firewall_rule(self, api: Any) -> dict[str, Any]:
        """Verify internet blocking is active for local-only devices.

        On the UCG Max, internet blocking is done per-device using v2
        Traffic Rules (one rule per MAC). This method checks that all
        assigned devices have their block rule in place.
        """
        if not self._assignments:
            return {"ok": True, "status": "no_devices_assigned",
                    "message": "No devices assigned to local-only yet. Assign a device first."}

        # Check existing traffic rules for our blocks.
        blocked = 0
        missing = []
        try:
            rules = await api.get_traffic_rules()
            rule_descs = {r.get("description", "").lower() for r in rules}
            for mac in self._assignments:
                if f"ub: {mac}" in rule_descs:
                    blocked += 1
                else:
                    missing.append(mac)
        except Exception as err:
            return {"ok": False, "error": f"Could not check rules: {err}"}

        # Create missing rules.
        created = 0
        for mac in missing:
            result = await self.block_device_internet(api, mac)
            if result.get("ok"):
                created += 1

        total = len(self._assignments)
        return {
            "ok": True,
            "status": "per_device",
            "total_devices": total,
            "already_blocked": blocked,
            "newly_blocked": created,
            "message": f"{blocked + created}/{total} devices have internet blocked",
        }

    async def _try_create_traffic_rule(self, api: Any) -> dict[str, Any]:
        """Try creating a v2 Traffic Rule (newer UCG Max firmware)."""
        # v2 Traffic Rules require ALL fields present, UPPERCASE action,
        # and proper schedule/bandwidth objects.
        # The UCG Max v2 API only supports per-client or per-network
        # rules, not per-subnet. So instead of one subnet rule, we
        # block internet for each device individually when it gets
        # assigned to local-only. This method creates a single rule
        # that blocks a specific MAC from internet.
        return {"ok": False, "error": "Subnet rules not supported — using per-device blocking instead"}

    async def block_device_internet(self, api: Any, mac: str) -> dict[str, Any]:
        """Block a specific device from internet using v2 Traffic Rules."""
        rule_payload = {
            "action": "BLOCK",
            "description": f"UB: {mac} local-only",
            "enabled": True,
            "matching_target": "INTERNET",
            "target_devices": [
                {"client_mac": mac.lower(), "type": "CLIENT"}
            ],
            "ip_addresses": [],
            "ip_ranges": [],
            "regions": [],
            "domains": [],
            "app_category_ids": [],
            "app_ids": [],
            "network_ids": [],
            "schedule": {
                "mode": "ALWAYS",
                "repeat_on_days": [],
                "time_all_day": False,
                "time_range_end": "00:00",
                "time_range_start": "00:00",
            },
            "bandwidth_limit": {
                "download_limit_kbps": 0,
                "enabled": False,
                "upload_limit_kbps": 0,
            },
        }

        try:
            result = await api.create_traffic_rule(rule_payload)
            rule_id = ""
            if isinstance(result, dict):
                rule_id = result.get("_id", "")
            _LOGGER.info("Blocked internet for %s (rule: %s)", mac, rule_id)
            return {"ok": True, "rule_id": rule_id, "mac": mac}
        except Exception as err:
            return {"ok": False, "error": str(err)}

    async def unblock_device_internet(self, api: Any, mac: str) -> dict[str, Any]:
        """Remove the internet block for a specific device."""
        try:
            rules = await api.get_traffic_rules()
            for rule in rules:
                desc = rule.get("description", "")
                if f"UB: {mac.lower()}" in desc.lower() or f"ub: {mac.lower()}" in desc.lower():
                    await api.delete_traffic_rule(rule["_id"])
                    _LOGGER.info("Unblocked internet for %s", mac)
                    return {"ok": True, "mac": mac}
            return {"ok": False, "error": "No matching rule found"}
        except Exception as err:
            return {"ok": False, "error": str(err)}

    async def _try_create_legacy_rule(self, api: Any) -> dict[str, Any]:
        """Legacy firewall rules — not supported on newer UCG Max."""
        return {"ok": False, "error": "Legacy API not supported on this controller"}

    async def get_firewall_status(self, api: Any) -> dict[str, Any]:
        """Check internet blocking status for local-only devices."""
        if not self._assignments:
            return {"exists": False, "message": "No devices assigned yet"}

        blocked_count = 0
        total = len(self._assignments)
        try:
            rules = await api.get_traffic_rules()
            rule_descs = {r.get("description", "").lower() for r in rules}
            for mac in self._assignments:
                if f"ub: {mac}" in rule_descs:
                    blocked_count += 1
        except Exception:
            pass

        return {
            "exists": blocked_count > 0,
            "enabled": blocked_count == total,
            "blocked_count": blocked_count,
            "total_devices": total,
            "name": f"Per-device internet blocking ({blocked_count}/{total})",
            "api": "v2_per_device",
        }
