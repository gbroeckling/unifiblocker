"""Persistent store for device classifications."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    STATE_IGNORED,
    STATE_NEW,
    STATE_QUARANTINED,
    STATE_TRUSTED,
    STORAGE_KEY,
    STORAGE_VERSION,
)

_LOGGER = logging.getLogger(__name__)


class DeviceStore:
    """Persist per-MAC device state across HA restarts.

    Data shape on disk::

        {
            "devices": {
                "aa:bb:cc:dd:ee:ff": {
                    "state": "trusted",
                    "name": "iPhone",
                    "first_seen": "2026-04-01T12:00:00",
                    "last_seen": "2026-04-08T09:30:00"
                },
                ...
            }
        }
    """

    VALID_STATES = {STATE_NEW, STATE_TRUSTED, STATE_IGNORED, STATE_QUARANTINED}

    def __init__(self, hass: HomeAssistant) -> None:
        self._hass = hass
        self._store = Store(hass, STORAGE_VERSION, STORAGE_KEY)
        self._devices: dict[str, dict[str, Any]] = {}
        self._meta: dict[str, Any] = {}
        # Bumped on every user-driven change (they all end in async_save) so
        # cached enrichment knows to rebuild before the next poll.
        self.rev = 0

    # ── lifecycle ────────────────────────────────────────────────────

    async def async_load(self) -> None:
        """Load stored data from disk."""
        data = await self._store.async_load()
        if data and isinstance(data, dict):
            self._devices = data.get("devices", {})
            self._meta = data.get("meta", {})
        _LOGGER.debug("Loaded %d device records", len(self._devices))

    async def async_save(self) -> None:
        """Persist current state to disk."""
        self.rev += 1
        await self._store.async_save(self._data())

    def schedule_save(self) -> None:
        """Debounced save for poll updates (last_seen changes every poll)."""
        self._store.async_delay_save(self._data, 60)

    def _data(self) -> dict[str, Any]:
        return {"devices": self._devices, "meta": self._meta}

    # ── new-camera tracking ──────────────────────────────────────────

    def new_cameras(self, macs: list[str]) -> list[str]:
        """Of *macs* (devices that look like cameras now), the ones never
        seen as a camera before. Marks them seen.

        The first call after an update only records what's already there
        and returns nothing, so upgrading doesn't announce every existing
        camera as new."""
        fresh = [m for m in (x.lower() for x in macs)
                 if not self._devices.get(m, {}).get("camera_seen")]
        if not fresh:
            if not self._meta.get("cameras_baselined"):
                self._meta["cameras_baselined"] = True
                self.schedule_save()
            return []
        for m in fresh:
            self._devices.setdefault(m, {"state": STATE_NEW})["camera_seen"] = True
        self.schedule_save()
        if not self._meta.get("cameras_baselined"):
            self._meta["cameras_baselined"] = True
            return []
        return fresh

    # ── queries ──────────────────────────────────────────────────────

    @property
    def devices(self) -> dict[str, dict[str, Any]]:
        return self._devices

    def get_state(self, mac: str) -> str:
        """Return the classification for *mac*, defaulting to ``new``."""
        entry = self._devices.get(mac.lower())
        return entry["state"] if entry else STATE_NEW

    def get_devices_by_state(self, state: str) -> dict[str, dict[str, Any]]:
        """Return all devices matching *state*."""
        return {
            mac: info
            for mac, info in self._devices.items()
            if info.get("state") == state
        }

    # ── mutations ────────────────────────────────────────────────────

    async def set_state(
        self,
        mac: str,
        state: str,
        *,
        name: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Set the classification for a device and persist."""
        mac = mac.lower()
        if state not in self.VALID_STATES:
            raise ValueError(f"Invalid state: {state}")

        entry = self._devices.setdefault(mac, {})
        entry["state"] = state
        if name is not None:
            entry["name"] = name
        if extra:
            entry.update(extra)
        await self.async_save()

    async def upsert_from_unifi(
        self, mac: str, *, name: str | None = None, ip: str | None = None,
        first_seen: str | None = None, last_seen: str | None = None
    ) -> None:
        """Update metadata from a UniFi poll without changing the state.

        If the device has never been seen before it gets state ``new``.
        Tracks IP changes in ip_history.
        """
        mac = mac.lower()
        entry = self._devices.get(mac)
        if entry is None:
            self._devices[mac] = {
                "state": STATE_NEW,
                "name": name or "",
                "current_ip": ip or "",
                "ip_history": [],
                "first_seen": first_seen or "",
                "last_seen": last_seen or "",
            }
        else:
            if name:
                entry["name"] = name
            if last_seen:
                entry["last_seen"] = last_seen
            # Track IP changes.
            if ip and ip != entry.get("current_ip", ""):
                old_ip = entry.get("current_ip", "")
                if old_ip:
                    history = entry.setdefault("ip_history", [])
                    history.append({
                        "ip": old_ip,
                        "until": last_seen or "",
                        "type": "observed",
                    })
                    # Keep last 20 entries.
                    if len(history) > 20:
                        entry["ip_history"] = history[-20:]
                entry["current_ip"] = ip
        # Batch-save happens in the coordinator after a full poll.

    def get_ip_history(self, mac: str) -> list[dict[str, Any]]:
        """Return IP history for a device."""
        entry = self._devices.get(mac.lower())
        if not entry:
            return []
        history = list(entry.get("ip_history", []))
        current = entry.get("current_ip", "")
        if current:
            history.append({"ip": current, "until": "now", "type": "current"})
        return history

    async def record_ip_change(
        self, mac: str, old_ip: str, new_ip: str, change_type: str = "reassignment"
    ) -> None:
        """Record a deliberate IP change (e.g. moving to local-only)."""
        mac = mac.lower()
        entry = self._devices.setdefault(mac, {"state": STATE_NEW})
        history = entry.setdefault("ip_history", [])
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        if old_ip:
            history.append({"ip": old_ip, "until": now, "type": change_type})
        entry["current_ip"] = new_ip
        if len(history) > 20:
            entry["ip_history"] = history[-20:]
        await self.async_save()

    def get_manual_category(self, mac: str) -> str | None:
        """Return the manual category override for *mac*, or None."""
        entry = self._devices.get(mac.lower())
        return entry.get("manual_category") if entry else None

    def get_all_manual_categories(self) -> dict[str, str]:
        """Return {mac: category} for all manually categorized devices."""
        return {
            mac: info["manual_category"]
            for mac, info in self._devices.items()
            if info.get("manual_category")
        }

    async def set_manual_category(
        self, mac: str, category: str, *, name: str | None = None
    ) -> None:
        """Set a manual category override and persist."""
        mac = mac.lower()
        entry = self._devices.setdefault(mac, {"state": STATE_NEW})
        entry["manual_category"] = category
        entry.pop("suggested_category", None)
        if name:
            # Kept separate from "name" so the next poll doesn't overwrite it.
            entry["custom_name"] = name
        await self.async_save()

    def get_custom_name(self, mac: str) -> str:
        """Return the name set from the panel, or ""."""
        entry = self._devices.get(mac.lower())
        return entry.get("custom_name", "") if entry else ""

    def get_suggestion(self, mac: str) -> dict[str, Any] | None:
        """Return the Quantify suggestion for *mac*, or None."""
        entry = self._devices.get(mac.lower())
        return entry.get("suggested_category") if entry else None

    async def set_suggestion(
        self, mac: str, category: str, *, confidence: str, description: str = ""
    ) -> None:
        """Remember a deep-scan guess without treating it as a user decision."""
        mac = mac.lower()
        entry = self._devices.setdefault(mac, {"state": STATE_NEW})
        entry["suggested_category"] = {
            "category": category,
            "confidence": confidence,
            "description": description,
        }
        await self.async_save()

    async def clear_manual_category(self, mac: str) -> None:
        """Remove the manual category override."""
        mac = mac.lower()
        entry = self._devices.get(mac)
        if entry:
            entry.pop("manual_category", None)
            await self.async_save()

    async def remove(self, mac: str) -> None:
        """Delete a device record entirely."""
        self._devices.pop(mac.lower(), None)
        await self.async_save()
