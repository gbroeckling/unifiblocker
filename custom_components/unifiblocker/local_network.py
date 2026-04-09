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

        # Store locally.
        self._assignments[mac] = {
            "ip": ip,
            "category": category,
            "name": name,
            "user_id": user_id,
        }
        await self.async_save()

        _LOGGER.info("Assigned %s → %s (category: %s)", mac, ip, category)
        return {"ok": True, "ip": ip, "mac": mac, "category": category}

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

        self._assignments.pop(mac, None)
        await self.async_save()
        return {"ok": True, "mac": mac}

    # ── Firewall rule ────────────────────────────────────────────────
    #
    # Tries v2 Traffic Rules API first (newer UCG Max firmware), then
    # falls back to legacy firewall rules API. Only ever creates a
    # rule that blocks 192.168.2.0/24 from reaching the internet.

    async def ensure_firewall_rule(self, api: Any) -> dict[str, Any]:
        """Create or verify the WAN-block rule for the local-only subnet.

        Tries v2 Traffic Rules first, falls back to legacy firewall rules.
        ONLY affects the configured local-only CIDR (default 192.168.2.0/24).
        """
        # Check if we already have a cached rule that still exists.
        existing = await self.get_firewall_status(api)
        if existing.get("exists"):
            return {"ok": True, "status": "exists", "rule_id": existing.get("rule_id", ""),
                    "api": existing.get("api", "unknown")}

        # Try v2 Traffic Rules API first (newer firmware).
        result = await self._try_create_traffic_rule(api)
        if result.get("ok"):
            return result

        # Fall back to legacy firewall rules API.
        result = await self._try_create_legacy_rule(api)
        return result

    async def _try_create_traffic_rule(self, api: Any) -> dict[str, Any]:
        """Try creating a v2 Traffic Rule (newer UCG Max firmware)."""
        # v2 Traffic Rules require ALL fields present, UPPERCASE action,
        # and proper schedule/bandwidth objects.
        rule_payload = {
            "action": "BLOCK",
            "description": FIREWALL_RULE_NAME,
            "enabled": True,
            "matching_target": "INTERNET",
            "target_devices": [],
            "ip_addresses": [
                {
                    "ip_or_subnet": self.cidr,
                    "ip_version": "v4",
                    "port_ranges": [],
                    "ports": [],
                }
            ],
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

        _LOGGER.info("Trying v2 Traffic Rule API: block %s → Internet", self.cidr)

        try:
            result = await api.create_traffic_rule(rule_payload)
            rule_id = ""
            if isinstance(result, dict):
                rule_id = result.get("_id", "")
            elif isinstance(result, list) and result:
                rule_id = result[0].get("_id", "")

            self._firewall_rule_id = rule_id or "traffic_rule"
            self._config["rule_api"] = "v2"
            await self.async_save()
            _LOGGER.info("Created v2 traffic rule for %s (ID: %s)", self.cidr, rule_id)
            return {"ok": True, "status": "created", "rule_id": rule_id, "api": "v2"}
        except Exception as err:
            _LOGGER.info("v2 Traffic Rule API failed: %s — trying legacy", err)
            return {"ok": False, "error": str(err)}

    async def _try_create_legacy_rule(self, api: Any) -> dict[str, Any]:
        """Try creating a legacy firewall rule."""
        rule_payload = {
            "name": FIREWALL_RULE_NAME,
            "enabled": True,
            "action": "drop",
            "ruleset": "WAN_OUT",
            "protocol": "all",
            "rule_index": 2000,
            "src_address": self.cidr,
            "logging": True,
        }

        _LOGGER.info("Trying legacy firewall rule API: drop %s on WAN_OUT", self.cidr)

        try:
            # Try to learn site_id from existing rules.
            try:
                existing = await api.get_firewall_rules()
                if existing:
                    for field in ["site_id"]:
                        if field in existing[0]:
                            rule_payload[field] = existing[0][field]
            except Exception:
                pass

            result = await api.create_firewall_rule(rule_payload)
            rule_id = ""
            if isinstance(result, dict):
                rule_id = result.get("_id", "")
            elif isinstance(result, list) and result:
                rule_id = result[0].get("_id", "")

            self._firewall_rule_id = rule_id or "legacy_rule"
            self._config["rule_api"] = "legacy"
            await self.async_save()
            _LOGGER.info("Created legacy firewall rule for %s (ID: %s)", self.cidr, rule_id)
            return {"ok": True, "status": "created", "rule_id": rule_id, "api": "legacy"}
        except Exception as err:
            return {"ok": False, "error": f"Both v2 and legacy APIs failed. Legacy error: {err}"}

    async def get_firewall_status(self, api: Any) -> dict[str, Any]:
        """Check if the WAN-block rule exists (checks both APIs)."""
        # Check v2 Traffic Rules.
        try:
            rules = await api.get_traffic_rules()
            for rule in rules:
                desc = rule.get("description", "")
                if FIREWALL_RULE_NAME in desc:
                    return {
                        "exists": True,
                        "enabled": rule.get("enabled", False),
                        "rule_id": rule.get("_id", ""),
                        "name": desc,
                        "action": rule.get("action", ""),
                        "api": "v2",
                    }
        except Exception:
            pass

        # Check legacy firewall rules.
        try:
            rules = await api.get_firewall_rules()
            for rule in rules:
                if rule.get("name") == FIREWALL_RULE_NAME:
                    return {
                        "exists": True,
                        "enabled": rule.get("enabled", False),
                        "rule_id": rule.get("_id", ""),
                        "name": FIREWALL_RULE_NAME,
                        "action": rule.get("action", ""),
                        "src_address": rule.get("src_address", ""),
                        "api": "legacy",
                    }
        except Exception:
            pass

        return {"exists": False}
