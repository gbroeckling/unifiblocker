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
from .home_automation import classify as classify_home_automation
from .insights import (
    camera_hotspots, containment_status, hourly_series, security_events,
    summarize_flows, traffic_spike, unifi_fingerprint,
)
from .vendor_lookup import CAMERA_CHIP_VENDORS, is_camera_like, lookup_vendor_safe

_LOGGER = logging.getLogger(__name__)

RESCAN_AFTER_S = 7 * 86400       # port scans and ONVIF results older than this get redone
DISCOVERY_EVERY_S = 6 * 3600     # ONVIF WS-Discovery
SECURITY_LOG_EVERY_S = 600       # system-log/all
TRAFFIC_EVERY_S = 900            # stat/report/hourly.user
ROGUE_EVERY_S = 1800             # stat/rogueap (Wi-Fi networks around us)
FLOWS_EVERY_S = 900              # v2 traffic-flows, per watched device
FLOWS_MAX_DEVICES = 30
ONVIF_PROBES_PER_PASS = 3
# Web ports a camera's ONVIF service usually sits on.
ONVIF_HINT_PORTS = frozenset({80, 2020, 8000, 8080, 8899})


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
        security: list[dict[str, Any]] | None = None,
        traffic: dict[str, list[int]] | None = None,
        hotspots: list[dict[str, Any]] | None = None,
        phone_home: dict[str, dict[str, Any]] | None = None,
        contained: set[str] | None = None,
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
        self.security = security or []      # SECURITY entries from system-log/all
        self.traffic = traffic or {}        # mac → bytes per hour, last 24 h
        self.hotspots = hotspots or []      # camera-looking Wi-Fi networks nearby
        self.phone_home = phone_home or {}  # mac → summarize_flows() of its logged flows
        self.contained = contained or set() # macs meant to be off the internet
        self._watched: set[str] = set()
        from .insights import events_by_mac
        self._security_by_mac = events_by_mac(self.security)
        self._contained_by_mac = events_by_mac(self.security, ours=True)
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
        """Security events: UniFi's system log on current firmware, plus
        IDS/IPS entries from stat/event on controllers that still have it."""
        return [e for e in self.security if not e.get("ours")] + [
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
            self._enriched[key]["home_automation"] = classify_home_automation(self._enriched[key])
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
            "onvif": self._get_onvif_for(mac, client.get("ip", "")),
            "vulns": self._vulns(client, camera, vendor, cat_data),
            "unifi_fingerprint": unifi_fingerprint(client),
            "security_events_24h": self._security_by_mac.get(mac_lower, 0),
            "blocked_by_rule_24h": self._contained_by_mac.get(mac_lower, 0),
            "traffic_24h": self.traffic.get(mac_lower),
            "traffic_spike": traffic_spike(self.traffic.get(mac_lower) or []),
            "phone_home": self.phone_home.get(mac_lower),
            "watched": mac_lower in self.phone_home or mac_lower in self._watched,
            "containment": containment_status(self.phone_home.get(mac_lower), mac_lower in self.contained),
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

    def _vulns(self, client: dict[str, Any], camera: bool, vendor: str,
               cat_data: dict[str, Any]) -> dict[str, Any] | None:
        """Firmware vulnerability check (vuln.py) for cameras and anything
        from a camera maker."""
        from .vuln import assess

        onvif = self.onvif.result_for(client.get("mac", ""), client.get("ip", "")) if self.onvif else None
        onvif = onvif if onvif and onvif.get("onvif") else {}
        manufacturer = onvif.get("manufacturer") or cat_data.get("onvif_manufacturer", "")
        model = onvif.get("model") or cat_data.get("onvif_model", "")
        firmware = onvif.get("firmware_version") or cat_data.get("onvif_firmware", "")
        result = assess(vendor, manufacturer, model, firmware)
        if result and not camera and not result["findings"]:
            return None   # an old firmware date on a non-camera isn't our business
        return result

    def _get_onvif_for(self, mac: str, ip: str) -> dict[str, Any] | None:
        """Look up the ONVIF result for a client. Returns only key fields."""
        if not self.onvif:
            return None
        result = self.onvif.result_for(mac, ip)
        if not result:
            return None
        # Only return essential fields — not the raw SOAP data.
        return {
            "onvif": result.get("onvif", False),
            "manufacturer": result.get("manufacturer", ""),
            "model": result.get("model", ""),
            "firmware_version": result.get("firmware_version", ""),
            "serial_number": result.get("serial_number", ""),
            "auth_required": bool(result.get("auth_required")),
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
        camera_policy: str = "block_internet",
        device_policy: str = "notify",
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
        # (mac, ip) pairs already port-scanned / ONVIF-probed this run, so a
        # device that fails doesn't get retried every poll.
        self._auto_scanned: set[tuple[str, str]] = set()
        self._onvif_tried: set[tuple[str, str]] = set()
        self._onvif_busy = False
        self._last_discovery = 0.0
        self._auto_scan_count = auto_scan_count
        self._camera_policy = camera_policy
        self._device_policy = device_policy
        # Slower-moving sources, refreshed on their own schedule (see *_EVERY_S).
        self._security: list[dict[str, Any]] = []
        self._traffic_rows: list[dict[str, Any]] = []
        self._rogue: list[dict[str, Any]] = []
        self._fetched_at: dict[str, float] = {}
        self._flows: dict[str, dict[str, Any] | None] = {}
        self._leak_announced: dict[str, float] = {}
        self.local_net: Any = None   # set by __init__ once it exists
        self._events_supported = True  # stat/event is gone on newer UniFi Network

    def _schedule_onvif(self, clients: list[dict[str, Any]], now_ts: float) -> None:
        """Start ONVIF discovery and probes in the background when due.

        Discovery runs at startup and every 6 h. A device gets a direct probe
        when its port scan shows a likely ONVIF port and we have no ONVIF
        result for it, it moved to a new IP, or the result is over a week
        old. Probes can take minutes, so they never hold up the poll.
        """
        if self._onvif_busy:
            return
        discover = now_ts - self._last_discovery >= DISCOVERY_EVERY_S
        targets: list[tuple[str, str]] = []
        if self.scanner:
            for client in clients:
                mac, ip = client.get("mac", "").lower(), client.get("ip", "")
                if not mac or not ip or (mac, ip) in self._onvif_tried:
                    continue
                scan = self.scanner.get_result(mac)
                if not scan or not ONVIF_HINT_PORTS & set(scan.get("open_ports") or []):
                    continue
                known = self.onvif.known_for(mac)
                if known and known.get("ip") == ip and now_ts - known.get("probe_time", 0) < RESCAN_AFTER_S:
                    continue
                targets.append((mac, ip))
                if len(targets) >= ONVIF_PROBES_PER_PASS:
                    break
        if not discover and not targets:
            return
        if discover:
            self._last_discovery = now_ts
        self._onvif_tried.update(targets)
        self._onvif_busy = True

        async def _run() -> None:
            try:
                if discover:
                    await self.onvif.discover_and_probe_all()
                for mac, ip in targets:
                    await self.onvif.probe_ip(ip)
                    self.onvif.note_probe(mac, ip)
            except Exception:
                _LOGGER.debug("ONVIF background pass failed", exc_info=True)
            finally:
                self._onvif_busy = False

        entry = getattr(self, "config_entry", None)
        if entry is not None:
            # Tied to the entry, so it's cancelled on unload/reload.
            entry.async_create_background_task(self.hass, _run(), "unifiblocker onvif")
        else:
            self.hass.async_create_background_task(_run(), "unifiblocker onvif")

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

        # Who's new (before the store learns about them).
        new_macs = self.store.new_devices([c.get("mac", "") for c in clients])

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
                if not mac or not ip or (mac, ip) in self._auto_scanned:
                    continue
                cached = self.scanner.get_result(mac)
                if cached and cached.get("status") == "complete":
                    # Already known: rescan only when it moved or the scan is old.
                    if cached.get("ip") == ip and now_ts - cached.get("scan_time", 0) < RESCAN_AFTER_S:
                        continue
                    scan_targets.append({"ip": ip, "mac": mac})
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
                self._auto_scanned.update((t["mac"], t["ip"]) for t in batch)
                _LOGGER.debug("Auto-scanning %d new/unknown devices", len(batch))
                try:
                    await self.scanner.scan_multiple(batch)
                except Exception:
                    _LOGGER.debug("Auto-scan error", exc_info=True)

        onvif_by_ip: dict[str, dict[str, Any]] | None = None
        if self.onvif:
            self._schedule_onvif(clients, now_ts)
            # Keyed by the client's current IP, but backed by what we know
            # about its MAC, so a camera that moved keeps its ONVIF identity.
            onvif_by_ip = {}
            for client in clients:
                mac, ip = client.get("mac", "").lower(), client.get("ip", "")
                if mac and ip:
                    self.onvif.link(mac, ip)
                    found = self.onvif.result_for(mac, ip)
                    if found:
                        onvif_by_ip[ip] = found

        # Categorize every client using ALL available signals.
        categories = categorize_devices(
            clients,
            dpi_data=dpi,
            manual_overrides=self.store.get_all_manual_categories(),
            scan_data=self.scanner.cache if self.scanner else None,
            onvif_data=onvif_by_ip,
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
        contained = self._contained_macs(clients)
        watched = self._watched_macs(clients, categories, contained)
        await self._refresh_slow_sources(now_ts, watched)
        data = UniFiBlockerData(
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
            security=self._security,
            traffic=hourly_series(self._traffic_rows),
            phone_home={m: s for m, s in self._flows.items() if s},
            contained=contained,
        )
        data._watched = set(watched)
        # Hotspots need to know which clients are cameras, so they come after.
        cams = {c.get("mac", "").lower(): (c.get("name") or c.get("hostname") or "")
                for c in clients if data.enrich_client(c).get("is_camera")}
        data.hotspots = camera_hotspots(self._rogue, cams)
        await self._announce_new_cameras(data)
        self._announce_new_devices(data, new_macs)
        self._announce_leaks(data, now_ts)
        return data

    def _announce_leaks(self, data: UniFiBlockerData, now_ts: float) -> None:
        """Fire unifiblocker_containment_failed (at most daily per device)
        when UniFi logs traffic it let through from a device that's meant to
        be cut off."""
        for client in data.clients:
            mac = client.get("mac", "").lower()
            e = data.enrich_client(client)
            if e.get("containment") != "leaking" or now_ts - self._leak_announced.get(mac, 0) < 86400:
                continue
            self._leak_announced[mac] = now_ts
            ph = e.get("phone_home") or {}
            self.hass.bus.async_fire(f"{DOMAIN}_containment_failed", {
                "mac": mac, "ip": e.get("ip", ""), "name": e.get("name", ""),
                "allowed": ph.get("allowed", 0),
                "destinations": [d["host"] for d in ph.get("top_destinations", [])][:5],
            })

    def _contained_macs(self, clients: list[dict[str, Any]]) -> set[str]:
        """Devices that are supposed to be off the internet: local-only,
        quarantined, or blocked on the controller."""
        out = {m.lower() for m in (self.local_net.assignments if self.local_net else {})}
        out |= {m.lower() for m in self.store.get_devices_by_state(STATE_QUARANTINED)}
        out |= {c.get("mac", "").lower() for c in clients if c.get("blocked")}
        out |= self.store.auto_blocked_macs()
        return out

    def _watched_macs(self, clients, categories, contained: set[str]) -> list[str]:
        """Who gets their traffic flows read: contained devices first (that's
        the proof), then cameras. Capped so one pass stays cheap."""
        cams = [c.get("mac", "").lower() for c in clients
                if categories.get(c.get("mac", "").lower(), {}).get("category") == "camera"]
        # Cloud-tied home automation too, after the cameras.
        ha = []
        for c in clients:
            mac = c.get("mac", "").lower()
            light = {"hostname": c.get("hostname", ""), "name": c.get("name", ""), "vendor": c.get("oui", ""),
                     "category": categories.get(mac, {}).get("category", "")}
            if (classify_home_automation(light) or {}).get("tier") in ("cloud", "cloud_local"):
                ha.append(mac)
        ordered = sorted(contained) + [m for m in cams + ha if m not in contained]
        return [m for m in ordered if m][:FLOWS_MAX_DEVICES]

    async def _refresh_slow_sources(self, now_ts: float, watched: list[str] | None = None) -> None:
        """Security log, hourly traffic and nearby Wi-Fi, each on its own
        schedule. Failures keep the last good copy; the poll goes on."""
        async def due(name: str, every: float, fetch) -> None:
            if now_ts - self._fetched_at.get(name, 0) < every:
                return
            self._fetched_at[name] = now_ts
            try:
                await fetch()
            except Exception:  # extras: never let them fail the poll
                _LOGGER.debug("Could not fetch %s", name, exc_info=True)

        async def sec() -> None:
            self._security = security_events(await self.api.get_system_log(24))

        async def traffic() -> None:
            self._traffic_rows = await self.api.get_hourly_traffic(25)

        async def rogue() -> None:
            self._rogue = await self.api.get_rogue_aps()

        await due("security", SECURITY_LOG_EVERY_S, sec)
        await due("traffic", TRAFFIC_EVERY_S, traffic)
        async def flows() -> None:
            # One query per device, so a chatty camera can't crowd out the rest.
            fresh = {}
            for mac in watched or []:
                try:
                    fresh[mac] = summarize_flows(await self.api.get_traffic_flows([mac], 24, max_pages=1))
                except Exception:
                    _LOGGER.debug("Could not fetch flows for %s", mac, exc_info=True)
                    fresh[mac] = self._flows.get(mac)
            self._flows = fresh

        await due("rogue", ROGUE_EVERY_S, rogue)
        await due("flows", FLOWS_EVERY_S, flows)

    def _announce_new_devices(self, data: UniFiBlockerData, new_macs: list[str]) -> None:
        """unifiblocker_new_device per device seen for the first time, plus
        one notification (new_device_policy). Cameras are handled by
        _announce_new_cameras."""
        if not new_macs:
            return
        fresh = []
        for client in data.clients:
            mac = client.get("mac", "").lower()
            if mac in new_macs:
                e = data.enrich_client(client)
                self.hass.bus.async_fire(f"{DOMAIN}_new_device", {
                    "mac": mac, "ip": e.get("ip", ""), "name": e.get("name", ""),
                    "vendor": e.get("vendor", ""), "category": e.get("category", ""),
                    "is_camera": bool(e.get("is_camera")),
                })
                if not e.get("is_camera"):
                    fresh.append(e)
        from .policy import on_new_devices
        on_new_devices(self.hass, self._device_policy, fresh)

    async def _announce_new_cameras(self, data: UniFiBlockerData) -> None:
        """Fire unifiblocker_new_camera once for each camera seen for the
        first time, so automations can notify, scan or isolate it, and apply
        new_camera_policy (see policy.py)."""
        from .policy import on_new_camera
        cams = {}
        for client in data.clients:
            e = data.enrich_client(client)
            if e.get("is_camera") and e.get("mac"):
                cams[e["mac"].lower()] = e
        for mac in self.store.new_cameras(list(cams)):
            e = cams[mac]
            onvif = e.get("onvif") or {}
            self.hass.bus.async_fire(f"{DOMAIN}_new_camera", {
                "mac": mac,
                "ip": e.get("ip", ""),
                "name": e.get("name", ""),
                "vendor": e.get("vendor", ""),
                "category_source": e.get("source", ""),
                "confidence": e.get("confidence", ""),
                "manufacturer": onvif.get("manufacturer") or e.get("onvif_manufacturer", ""),
                "model": onvif.get("model") or e.get("onvif_model", ""),
            })
            await on_new_camera(self.hass, self._camera_policy, self.api, self.local_net, self.store, e)
