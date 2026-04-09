"""DataUpdateCoordinator for UniFi Blocker."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, STATE_NEW, STATE_QUARANTINED, STATE_TRUSTED, STATE_IGNORED
from .device_store import DeviceStore
from .unifi_api import UniFiApi, UniFiApiError
from .vendor_lookup import lookup_vendor_safe

_LOGGER = logging.getLogger(__name__)


class UniFiBlockerData:
    """Snapshot returned by the coordinator after each poll."""

    def __init__(
        self,
        clients: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        store: DeviceStore,
    ) -> None:
        self.clients = clients
        self.devices = devices
        self.store = store

    # ── convenience counts ───────────────────────────────────────────

    @property
    def total_clients(self) -> int:
        return len(self.clients)

    @property
    def new_devices(self) -> list[dict[str, Any]]:
        """Clients that haven't been classified yet."""
        return [
            c for c in self.clients
            if self.store.get_state(c.get("mac", "")) == STATE_NEW
        ]

    @property
    def new_count(self) -> int:
        return len(self.new_devices)

    @property
    def blocked_count(self) -> int:
        return sum(1 for c in self.clients if c.get("blocked", False))

    @property
    def quarantined_macs(self) -> set[str]:
        return set(self.store.get_devices_by_state(STATE_QUARANTINED).keys())

    @property
    def trusted_count(self) -> int:
        return len(self.store.get_devices_by_state(STATE_TRUSTED))

    @property
    def ignored_count(self) -> int:
        return len(self.store.get_devices_by_state(STATE_IGNORED))

    def client_by_mac(self, mac: str) -> dict[str, Any] | None:
        mac = mac.lower()
        for c in self.clients:
            if c.get("mac", "").lower() == mac:
                return c
        return None

    def enrich_client(self, client: dict[str, Any]) -> dict[str, Any]:
        """Return a display-friendly dict for a single client."""
        mac = client.get("mac", "")
        return {
            "mac": mac,
            "name": client.get("name") or client.get("hostname") or "",
            "hostname": client.get("hostname", ""),
            "ip": client.get("ip", ""),
            "vendor": client.get("oui") or lookup_vendor_safe(mac),
            "network": client.get("network", ""),
            "blocked": client.get("blocked", False),
            "wired": client.get("is_wired", False),
            "rssi": client.get("rssi"),
            "signal": client.get("signal"),
            "channel": client.get("channel"),
            "radio": client.get("radio"),
            "essid": client.get("essid", ""),
            "experience": client.get("satisfaction"),
            "uptime_seconds": client.get("uptime"),
            "tx_bytes": client.get("tx_bytes"),
            "rx_bytes": client.get("rx_bytes"),
            "state": self.store.get_state(mac),
            "first_seen": client.get("first_seen"),
            "last_seen": client.get("last_seen"),
        }

    def all_clients_enriched(self) -> list[dict[str, Any]]:
        """Return enriched dicts for every connected client."""
        return [self.enrich_client(c) for c in self.clients]


class UniFiBlockerCoordinator(DataUpdateCoordinator[UniFiBlockerData]):
    """Poll the UniFi controller and reconcile device states."""

    def __init__(
        self,
        hass: HomeAssistant,
        api: UniFiApi,
        store: DeviceStore,
        update_interval: int,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )
        self.api = api
        self.store = store

    async def _async_update_data(self) -> UniFiBlockerData:
        """Fetch clients from the controller and update the store."""
        try:
            clients = await self.api.get_clients()
            devices = await self.api.get_devices()
        except UniFiApiError as err:
            raise UpdateFailed(f"Error communicating with UniFi: {err}") from err

        now = datetime.now(timezone.utc).isoformat()

        # Merge every active client into the persistent store.
        for client in clients:
            mac = client.get("mac", "").lower()
            if not mac:
                continue
            name = client.get("name") or client.get("hostname") or ""
            first_seen = client.get("first_seen")
            if first_seen and isinstance(first_seen, (int, float)):
                first_seen = datetime.fromtimestamp(first_seen, tz=timezone.utc).isoformat()
            await self.store.upsert_from_unifi(
                mac, name=name, first_seen=first_seen, last_seen=now
            )

        # Persist once after the full batch.
        await self.store.async_save()

        return UniFiBlockerData(clients=clients, devices=devices, store=self.store)
