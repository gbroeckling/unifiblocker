"""Learning engine — learns from manual categorizations.

When a user manually categorizes a device, the system extracts
patterns from that device (vendor string, hostname prefix, MAC
prefix, open ports) and applies them to other uncategorized devices.

Example flow:
  1. User sees unknown device with vendor "Hangzhou Hikvision Digital
     Technology Co.,Ltd." and hostname "IPC-D4309F"
  2. User manually sets category to "camera"
  3. System learns:
     - vendor "hangzhou hikvision" → camera
     - hostname prefix "ipc-" → camera
     - MAC prefix "c0:56:e3" → camera
  4. Other uncategorized devices with any of these patterns
     get auto-categorized as "camera" (source="learned")

Patterns persist to disk and accumulate over time.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

STORAGE_KEY = "unifiblocker_learned"
STORAGE_VERSION = 1


class LearnedPatterns:
    """Persistent store of patterns learned from manual categorizations."""

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        # vendor_keyword (lowercase) → category
        self._vendor_rules: dict[str, str] = {}
        # hostname prefix (lowercase, min 3 chars) → category
        self._hostname_rules: dict[str, str] = {}
        # MAC prefix (first 3 octets, lowercase) → category
        self._mac_rules: dict[str, str] = {}
        # frozenset of port numbers → category
        self._port_rules: list[dict[str, Any]] = []

    async def async_load(self) -> None:
        data = await self._store.async_load()
        if data and isinstance(data, dict):
            self._vendor_rules = data.get("vendor_rules", {})
            self._hostname_rules = data.get("hostname_rules", {})
            self._mac_rules = data.get("mac_rules", {})
            self._port_rules = data.get("port_rules", [])
        _LOGGER.info(
            "Loaded learned patterns: %d vendor, %d hostname, %d mac, %d port rules",
            len(self._vendor_rules), len(self._hostname_rules),
            len(self._mac_rules), len(self._port_rules),
        )

    async def async_save(self) -> None:
        await self._store.async_save({
            "vendor_rules": self._vendor_rules,
            "hostname_rules": self._hostname_rules,
            "mac_rules": self._mac_rules,
            "port_rules": self._port_rules,
        })

    # ── Learn from a manual categorization ───────────────────────────

    async def learn_from_device(
        self,
        category: str,
        *,
        mac: str = "",
        vendor: str = "",
        hostname: str = "",
        open_ports: list[int] | None = None,
    ) -> dict[str, Any]:
        """Extract patterns from a manually categorized device.

        Returns a dict of what was learned.
        """
        learned: dict[str, Any] = {"category": category, "rules_added": []}

        # 1. Vendor keyword learning.
        #    Extract significant words from the vendor string.
        if vendor and vendor != "Unknown":
            keywords = self._extract_vendor_keywords(vendor)
            for kw in keywords:
                if kw not in self._vendor_rules:
                    self._vendor_rules[kw] = category
                    learned["rules_added"].append(f"vendor '{kw}' → {category}")

        # 2. Hostname prefix learning.
        #    Learn the prefix up to the first number sequence.
        if hostname:
            prefix = self._extract_hostname_prefix(hostname)
            if prefix and len(prefix) >= 3 and prefix not in self._hostname_rules:
                self._hostname_rules[prefix] = category
                learned["rules_added"].append(f"hostname '{prefix}*' → {category}")

        # 3. MAC prefix learning.
        #    Learn the first 3 octets (OUI).
        if mac:
            mac_prefix = mac.lower().replace("-", ":")[0:8]
            if mac_prefix and len(mac_prefix) == 8 and mac_prefix not in self._mac_rules:
                self._mac_rules[mac_prefix] = category
                learned["rules_added"].append(f"MAC '{mac_prefix}:*' → {category}")

        # 4. Port combination learning.
        #    Only learn if there are distinctive ports open.
        if open_ports and len(open_ports) >= 1:
            # Filter to non-common ports (skip 80, 443, 53, etc.)
            common = {22, 53, 80, 443, 123, 5353}
            distinctive = sorted(set(open_ports) - common)
            if distinctive:
                # Check if we already have a similar rule.
                existing = any(
                    set(r["ports"]) == set(distinctive) for r in self._port_rules
                )
                if not existing:
                    self._port_rules.append({
                        "ports": distinctive,
                        "category": category,
                    })
                    learned["rules_added"].append(
                        f"ports {distinctive} → {category}"
                    )

        if learned["rules_added"]:
            await self.async_save()
            _LOGGER.info(
                "Learned %d new rules from %s categorization: %s",
                len(learned["rules_added"]), category,
                "; ".join(learned["rules_added"]),
            )

        return learned

    # ── Apply learned patterns ───────────────────────────────────────

    def match_device(
        self,
        mac: str = "",
        vendor: str = "",
        hostname: str = "",
        open_ports: list[int] | None = None,
    ) -> dict[str, Any] | None:
        """Check if a device matches any learned pattern.

        Returns the best match or None.
        """
        matches: list[tuple[str, str, str]] = []  # (category, source, detail)

        # 1. Vendor match.
        if vendor and vendor != "Unknown":
            vendor_lower = vendor.lower()
            for kw, cat in self._vendor_rules.items():
                if kw in vendor_lower:
                    matches.append((cat, "learned_vendor", f"vendor contains '{kw}'"))

        # 2. Hostname match.
        if hostname:
            hn_lower = hostname.lower()
            for prefix, cat in self._hostname_rules.items():
                if hn_lower.startswith(prefix) or prefix in hn_lower:
                    matches.append((cat, "learned_hostname", f"hostname matches '{prefix}*'"))

        # 3. MAC prefix match.
        if mac:
            mac_prefix = mac.lower().replace("-", ":")[0:8]
            if mac_prefix in self._mac_rules:
                cat = self._mac_rules[mac_prefix]
                matches.append((cat, "learned_mac", f"MAC prefix {mac_prefix}"))

        # 4. Port match.
        if open_ports:
            port_set = set(open_ports)
            for rule in self._port_rules:
                rule_ports = set(rule["ports"])
                # Match if the device has ALL the learned ports.
                if rule_ports.issubset(port_set):
                    matches.append((
                        rule["category"], "learned_ports",
                        f"ports {rule['ports']}"
                    ))

        if not matches:
            return None

        # Return the most common category among matches.
        cat_counts: dict[str, int] = {}
        for cat, _, _ in matches:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        best_cat = max(cat_counts, key=cat_counts.get)

        return {
            "category": best_cat,
            "confidence": "medium" if len(matches) > 1 else "low",
            "source": "learned",
            "matches": [{"source": s, "detail": d} for _, s, d in matches if _ == best_cat],
        }

    def get_suggestions(
        self, devices: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Find uncategorized devices that match learned patterns.

        Returns devices with suggested categories.
        """
        suggestions = []
        for dev in devices:
            if dev.get("category") not in ("unknown", None):
                continue
            match = self.match_device(
                mac=dev.get("mac", ""),
                vendor=dev.get("vendor", ""),
                hostname=dev.get("hostname") or dev.get("name", ""),
                open_ports=dev.get("scan_result", {}).get("open_ports"),
            )
            if match:
                suggestions.append({
                    **dev,
                    "suggested_category": match["category"],
                    "suggestion_confidence": match["confidence"],
                    "suggestion_matches": match["matches"],
                })
        return suggestions

    # ── Helpers ──────────────────────────────────────────────────────

    def _extract_vendor_keywords(self, vendor: str) -> list[str]:
        """Extract significant keywords from a vendor string.

        'Hangzhou Hikvision Digital Technology Co.,Ltd.'
        → ['hangzhou hikvision', 'hikvision']
        """
        vendor_lower = vendor.lower()
        # Remove common suffixes.
        for suffix in [" co.,ltd.", " co., ltd.", " inc.", " corp.",
                       " corporation", " ltd.", " ltd", " llc",
                       " gmbh", " ag", " s.a."]:
            vendor_lower = vendor_lower.replace(suffix, "")
        vendor_lower = vendor_lower.strip()

        keywords = []
        # Full cleaned vendor string.
        if len(vendor_lower) >= 4:
            keywords.append(vendor_lower)
        # Individual significant words (4+ chars).
        words = vendor_lower.split()
        for word in words:
            word = word.strip(",.()[]")
            if len(word) >= 4 and word not in ("technology", "digital",
                    "electronic", "electronics", "communications",
                    "international", "systems", "network", "devices",
                    "solutions", "group", "global", "company"):
                keywords.append(word)
        return keywords

    def _extract_hostname_prefix(self, hostname: str) -> str:
        """Extract the prefix of a hostname before numbers.

        'IPC-D4309F' → 'ipc-'
        'ESP-Living-Room' → 'esp-'
        'DESKTOP-ABC123' → 'desktop-'
        'camera-01' → 'camera-'
        """
        hn = hostname.lower().strip()
        # Find the prefix before the first digit sequence.
        match = re.match(r'^([a-z][\w-]*?[-_]?)(?=\d)', hn)
        if match:
            return match.group(1)
        # If no digits, use the first segment before a dash/underscore
        # if it's followed by something that looks like an ID.
        parts = re.split(r'[-_]', hn)
        if len(parts) >= 2 and len(parts[0]) >= 3:
            return parts[0] + "-"
        return ""

    # ── Info for display ─────────────────────────────────────────────

    @property
    def rules_summary(self) -> dict[str, Any]:
        return {
            "vendor_rules": dict(self._vendor_rules),
            "hostname_rules": dict(self._hostname_rules),
            "mac_rules": dict(self._mac_rules),
            "port_rules": list(self._port_rules),
            "total_rules": (
                len(self._vendor_rules) + len(self._hostname_rules) +
                len(self._mac_rules) + len(self._port_rules)
            ),
        }
