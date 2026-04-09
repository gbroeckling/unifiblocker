"""DataUpdateCoordinator for UniFi Blocker."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, STATE_NEW, STATE_QUARANTINED, STATE_TRUSTED, STATE_IGNORED
from .device_categorizer import categorize_all_clients as categorize_devices, get_category_counts
from .device_store import DeviceStore
from .port_identify import analyze_dpi_entry
from .suspicious_traffic import analyze_all_clients
from .unifi_api import UniFiApi, UniFiApiError
from .vendor_lookup import is_camera_like, lookup_vendor_safe

_LOGGER = logging.getLogger(__name__)


class UniFiBlockerData:
    """Snapshot returned by the coordinator after each poll."""

    def __init__(
        self,
        clients: list[dict[str, Any]],
        devices: list[dict[str, Any]],
        store: DeviceStore,
        suspicion: dict[str, dict[str, Any]],
        events: list[dict[str, Any]],
        health: dict[str, Any],
        dpi: dict[str, dict[str, Any]],
        categories: dict[str, dict[str, Any]],
    ) -> None:
        self.clients = clients
        self.devices = devices
        self.store = store
        self.suspicion = suspicion          # mac → analysis result
        self.events = events                # recent IDS/IPS events
        self.health = health                # connection + subsystem health
        self.dpi = dpi                      # mac → DPI analysis result
        self.categories = categories        # mac → category result

    @property
    def category_counts(self) -> dict[str, int]:
        return get_category_counts(self.categories)

    def clients_by_category(self, category: str) -> list[dict[str, Any]]:
        """Return clients matching a specific category."""
        return [
            c for c in self.clients
            if self.categories.get(c.get("mac", "").lower(), {}).get("category") == category
        ]

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

    @property
    def suspicious_clients(self) -> list[dict[str, Any]]:
        """Clients flagged as suspicious."""
        return [
            c for c in self.clients
            if self.suspicion.get(c.get("mac", "").lower(), {}).get("suspicious")
        ]

    @property
    def suspicious_count(self) -> int:
        return len(self.suspicious_clients)

    @property
    def threat_events(self) -> list[dict[str, Any]]:
        """IDS/IPS events from the controller."""
        return [
            e for e in self.events
            if e.get("key", "").startswith("EVT_IPS")
            or "threat" in e.get("msg", "").lower()
            or "intrusion" in e.get("msg", "").lower()
            or "attack" in e.get("msg", "").lower()
        ]

    def client_by_mac(self, mac: str) -> dict[str, Any] | None:
        mac = mac.lower()
        for c in self.clients:
            if c.get("mac", "").lower() == mac:
                return c
        return None

    def enrich_client(self, client: dict[str, Any]) -> dict[str, Any]:
        """Return a display-friendly dict for a single client."""
        mac = client.get("mac", "")
        mac_lower = mac.lower()
        susp = self.suspicion.get(mac_lower, {})
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
            # ── suspicious traffic fields ────────────────────────────
            "suspicious": susp.get("suspicious", False),
            "threat_level": susp.get("threat_level", "none"),
            "suspicion_score": susp.get("score", 0),
            "suspicion_flags": susp.get("flags", []),
            # ── camera detection ─────────────────────────────────────
            "is_camera": is_camera_like(
                mac,
                client.get("hostname") or client.get("name") or "",
                client.get("oui") or lookup_vendor_safe(mac),
            ),
            # ── DPI / traffic analysis ───────────────────────────────
            "dpi": self.dpi.get(mac_lower, {}),
            # ── device category ───────────────────────────────────────
            **(self.categories.get(mac_lower, {})),
            # ── ONVIF device info (if probed) ────────────────────────
            "onvif": self._get_onvif_for_ip(client.get("ip", "")),
        }

    def _get_onvif_for_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up ONVIF probe result for an IP."""
        if not self.onvif or not ip:
            return None
        return self.onvif.get_result(ip)

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
        scanner: Any = None,
        onvif: Any = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=update_interval),
        )
        self.api = api
        self.store = store
        self.scanner = scanner
        self.onvif = onvif
        self._auto_scanned: set[str] = set()  # MACs already auto-scanned

    async def _async_update_data(self) -> UniFiBlockerData:
        """Fetch clients from the controller and update the store."""
        try:
            clients = await self.api.get_clients()
            devices = await self.api.get_devices()
        except UniFiApiError as err:
            raise UpdateFailed(f"Error communicating with UniFi: {err}") from err

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        now_ts = now.timestamp()

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
                mac, name=name, first_seen=first_seen, last_seen=now_iso
            )

        # Persist once after the full batch.
        await self.store.async_save()

        # Run suspicious-traffic analysis on every client.
        suspicion = analyze_all_clients(
            clients,
            now_ts=now_ts,
            store_get_state=self.store.get_state,
        )

        # Pull IDS/IPS events, health, and DPI (best-effort, don't fail the poll).
        events: list[dict[str, Any]] = []
        health: dict[str, Any] = {}
        dpi: dict[str, dict[str, Any]] = {}
        try:
            events = await self.api.get_events(limit=100)
        except UniFiApiError:
            _LOGGER.debug("Could not fetch events", exc_info=True)
        try:
            health = await self.api.check_health()
        except UniFiApiError:
            _LOGGER.debug("Could not fetch health", exc_info=True)
        try:
            raw_dpi = await self.api.get_dpi_stats()
            for entry in raw_dpi:
                mac_key = entry.get("mac", "").lower()
                if mac_key:
                    dpi[mac_key] = analyze_dpi_entry(entry)
        except UniFiApiError:
            _LOGGER.debug("Could not fetch DPI stats", exc_info=True)

        # Auto-scan new/unknown devices that have an IP.
        if self.scanner:
            scan_targets = []
            for client in clients:
                mac = client.get("mac", "").lower()
                ip = client.get("ip", "")
                if not mac or not ip or mac in self._auto_scanned:
                    continue
                state = self.store.get_state(mac)
                vendor = client.get("oui") or lookup_vendor_safe(mac)
                hostname = client.get("hostname") or client.get("name") or ""
                # Auto-scan if: new state, or unknown vendor, or camera chip vendor, or no hostname
                from .vendor_lookup import CAMERA_CHIP_VENDORS
                if state == "new" or vendor == "Unknown" or vendor in CAMERA_CHIP_VENDORS or not hostname.strip():
                    scan_targets.append({"ip": ip, "mac": mac})
                    self._auto_scanned.add(mac)

            # Scan up to 5 devices per poll cycle to avoid overwhelming the network.
            if scan_targets:
                _LOGGER.info("Auto-scanning %d new/unknown devices", min(len(scan_targets), 5))
                try:
                    await self.scanner.scan_multiple(scan_targets[:5])
                except Exception:
                    _LOGGER.debug("Auto-scan error", exc_info=True)

        # Categorize every client using ALL available signals.
        categories = categorize_devices(
            clients,
            dpi_data=dpi,
            manual_overrides=self.store.get_all_manual_categories(),
            scan_data=self.scanner.cache if self.scanner else None,
            onvif_data=self.onvif.cache if self.onvif else None,
        )

        return UniFiBlockerData(
            clients=clients,
            devices=devices,
            store=self.store,
            suspicion=suspicion,
            events=events,
            health=health,
            dpi=dpi,
            categories=categories,
        )
