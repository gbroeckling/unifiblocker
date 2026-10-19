"""DataUpdateCoordinator for UniFi Blocker."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, STATE_NEW, STATE_QUARANTINED, STATE_TRUSTED, STATE_IGNORED
from .device_categorizer import categorize_all_clients as categorize_devices, get_category_counts
from . import usage_report
from .device_store import DeviceStore
from .miners import MinerTracker
from .port_identify import analyze_dpi_entry
from .suspicious_traffic import analyze_all_clients
from .unifi_api import UniFiApi, UniFiApiError
from .vendor_lookup import CAMERA_CHIP_VENDORS, is_camera_like, lookup_vendor_safe

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
        miners: list[dict[str, Any]] | None = None,
        onvif: Any = None,
    ) -> None:
        self.clients = clients
        self.devices = devices
        self.store = store
        self.suspicion = suspicion          # mac → analysis result
        self.events = events                # recent IDS/IPS events
        self.health = health                # connection + subsystem health
        self.dpi = dpi                      # mac → DPI analysis result
        self.categories = categories        # mac → category result
        self.miners = miners or []          # list of rig dicts (see miners.py)
        self.onvif = onvif                  # OnvifProbe, used for enrichment
        # Several entities enrich the same clients on every update; do it once
        # per poll. Each poll builds a new UniFiBlockerData, so this never
        # outlives the data it was built from.
        self._enriched: dict[str, dict[str, Any]] = {}
        self._enriched_rev = store.rev

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
        key = client.get("mac", "").lower()
        if self._enriched_rev != self.store.rev:
            # Trust/category/etc. changed since we cached; HA debounces the
            # refresh that follows, so don't wait for it.
            self._enriched.clear()
            self._enriched_rev = self.store.rev
        if key in self._enriched:
            # Copy: some callers add keys (scan_result) to what they get back.
            return dict(self._enriched[key])
        try:
            self._enriched[key] = self._do_enrich(client)
            return dict(self._enriched[key])
        except Exception as err:
            _LOGGER.error("Enrich failed for %s: %s", client.get("mac", "?"), err, exc_info=True)
            return {
                "mac": client.get("mac", ""),
                "name": self.store.get_custom_name(client.get("mac", "")) or client.get("name") or client.get("hostname") or "",
                "ip": client.get("ip", ""),
                "vendor": client.get("oui", "Unknown"),
                "category": "unknown", "category_label": "Unknown",
                "category_icon": "❓", "state": "new",
                "suspicious": False, "threat_level": "none",
                "is_camera": False, "confidence": "low",
            }

    def _do_enrich(self, client: dict[str, Any]) -> dict[str, Any]:
        mac = client.get("mac", "")
        mac_lower = mac.lower()
        susp = self.suspicion.get(mac_lower, {})
        cat_data = self.categories.get(mac_lower, {})
        vendor = client.get("oui") or lookup_vendor_safe(mac)
        hostname = client.get("hostname") or client.get("name") or ""

        try:
            camera = is_camera_like(mac, hostname, vendor)
        except Exception:
            camera = False
        # ONVIF, port scans and manual overrides all land in the category.
        camera = camera or cat_data.get("category") == "camera"

        # Panel rename, then the UniFi alias, then whatever the device calls itself.
        display_name = (
            self.store.get_custom_name(mac) or client.get("name") or client.get("hostname") or ""
        )

        return {
            "mac": mac,
            "name": display_name,
            "hostname": client.get("hostname", ""),
            "ip": client.get("ip", ""),
            "vendor": vendor,
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
            "suspicious": susp.get("suspicious", False),
            "threat_level": susp.get("threat_level", "none"),
            "suspicion_score": susp.get("score", 0),
            "suspicion_flags": susp.get("flags", []),
            "is_camera": camera,
            "dpi": self._slim_dpi(mac_lower),
            "category": cat_data.get("category", "unknown"),
            "category_label": cat_data.get("category_label", "Unknown"),
            "category_icon": cat_data.get("category_icon", "❓"),
            "confidence": cat_data.get("confidence", "low"),
            "source": cat_data.get("source", "none"),
            "onvif_manufacturer": cat_data.get("onvif_manufacturer", ""),
            "onvif_model": cat_data.get("onvif_model", ""),
            "onvif_firmware": cat_data.get("onvif_firmware", ""),
            "onvif_serial": cat_data.get("onvif_serial", ""),
            "onvif": self._get_onvif_for_ip(client.get("ip", "")),
            "ip_history": self.store.get_ip_history(mac),
            "manual_category": self.store.get_manual_category(mac),
            "suggested_category": self.store.get_suggestion(mac),
        }

    def _slim_dpi(self, mac_lower: str) -> dict[str, Any]:
        """Return DPI data with only the essential fields."""
        dpi = self.dpi.get(mac_lower)
        if not dpi:
            return {}
        return {
            "total_rx_mb": dpi.get("total_rx_mb", 0),
            "total_tx_mb": dpi.get("total_tx_mb", 0),
            "top_categories": (dpi.get("top_categories") or [])[:5],
            "flags": dpi.get("flags", []),
        }

    def _get_onvif_for_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up ONVIF probe result for an IP. Returns only key fields."""
        if not self.onvif or not ip:
            return None
        result = self.onvif.get_result(ip)
        if not result:
            return None
        # Only return essential fields — not the raw SOAP data.
        return {
            "onvif": result.get("onvif", False),
            "manufacturer": result.get("manufacturer", ""),
            "model": result.get("model", ""),
            "firmware_version": result.get("firmware_version", ""),
            "serial_number": result.get("serial_number", ""),
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
        scanner: Any = None,
        onvif: Any = None,
        learned: Any = None,
        auto_scan_count: int = 5,
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
        self.learned = learned
        self.miners = MinerTracker(scanner)
        self._auto_scanned: set[str] = set()  # MACs already auto-scanned
        self._auto_scan_count = auto_scan_count
        self._events_supported = True  # stat/event is gone on newer UniFi Network

    async def _async_update_data(self) -> UniFiBlockerData:
        """Fetch clients from the controller and update the store."""
        started = time.monotonic()
        try:
            clients = await self.api.get_clients()
            devices = await self.api.get_devices()
        except UniFiApiError as err:
            usage_report.record_poll(time.monotonic() - started, ok=False)
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
                mac, name=name, ip=client.get("ip", ""),
                first_seen=first_seen, last_seen=now_iso,
            )

        # Persist once after the full batch, debounced so we don't hit the
        # disk on every poll.
        self.store.schedule_save()

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
        if self._events_supported:
            try:
                events = await self.api.get_events(limit=100)
            except UniFiApiError as err:
                if str(err).startswith("404"):
                    self._events_supported = False
                    _LOGGER.info("Controller has no stat/event endpoint, not polling it")
                else:
                    _LOGGER.debug("Could not fetch events", exc_info=True)
        try:
            health = await self.api.check_health()
        except Exception:
            _LOGGER.debug("Could not fetch health", exc_info=True)
        # If we got clients successfully, the connection IS working
        # even if the health endpoint failed.
        if clients and not health.get("connection_ok"):
            health["connection_ok"] = True
            health["hostname"] = health.get("hostname", "")
            health["version"] = health.get("version", "")
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
                if state == "new" or vendor == "Unknown" or vendor in CAMERA_CHIP_VENDORS or not hostname.strip():
                    scan_targets.append({"ip": ip, "mac": mac})

            # Scan a few devices per poll cycle (auto_scan_count option) so we
            # don't hammer the network. 0 turns auto-scan off.
            # Only mark the ones we actually scan, the rest get picked up next poll.
            if scan_targets and self._auto_scan_count > 0:
                batch = scan_targets[:self._auto_scan_count]
                self._auto_scanned.update(t["mac"] for t in batch)
                _LOGGER.debug("Auto-scanning %d new/unknown devices", len(batch))
                try:
                    await self.scanner.scan_multiple(batch)
                except Exception:
                    _LOGGER.debug("Auto-scan error", exc_info=True)

        # Categorize every client using ALL available signals.
        categories = categorize_devices(
            clients,
            dpi_data=dpi,
            manual_overrides=self.store.get_all_manual_categories(),
            scan_data=self.scanner.cache if self.scanner else None,
            onvif_data=self.onvif.cache if self.onvif else None,
            learned_patterns=self.learned,
        )

        # Probe any miners flagged by the port scan or vendor OUI and pull
        # live profitability. Goldshell rigs are detected by vendor since
        # they don't always expose port 4028.
        miners: list[dict[str, Any]] = []
        try:
            session = async_get_clientsession(self.hass)
            miners = await self.miners.async_update(session, clients)
        except Exception:
            _LOGGER.debug("Miner tracker update failed", exc_info=True)

        usage_report.record_poll(time.monotonic() - started, ok=True)
        return UniFiBlockerData(
            clients=clients,
            devices=devices,
            store=self.store,
            suspicion=suspicion,
            events=events,
            health=health,
            dpi=dpi,
            categories=categories,
            miners=miners,
            onvif=self.onvif,
        )
