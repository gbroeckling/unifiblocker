"""Opt-in usage and issue report — "help improve UniFi Blocker".

OFF by default. Nothing here sends anything until an admin turns it on in the
panel (Overview → Help improve UniFi Blocker), where Preview shows the exact
JSON that will go. Same promise as PadSpan's report: counts and versions,
never things.

What goes out:
    integration, Home Assistant and Python versions; the controller's
        major.minor version
    a few settings: poll interval, auto-scan count, whether the local-only
        subnet is the default one
    how many clients, wired/wireless, cameras, suspicious, new, trusted,
        quarantined, blocked, local-only, miners; clients per category;
        devices matching each vendor advisory (Hikvision, Dahua, ...)
    how often each tool was used since the last report (an allow-listed
        vocabulary — see EVENTS) and which panel views were opened
    health: poll count, failures and timing; controller API errors by
        endpoint and status; warnings and errors logged per module; slow
        entity updates and oversized recorder attributes for our entities

Never: MAC or IP addresses, hostnames, device names, vendor strings from the
network, entity ids, the controller's address or site, timestamps finer than
the day. `assert_shareable` walks every value before a send and refuses the
whole report if anything identifier-shaped is in it.

The install id is a random UUID minted the first time the report is turned
on, so installs can be counted rather than pings. "New anonymous ID" replaces
it. At most one POST per UTC day to REPORT_URL, a few KB, hard cap 8 KB.
Failure is silent; the counters stay and go with the next report.
"""
from __future__ import annotations

import collections
from datetime import timedelta
import functools
import json
import logging
import platform
import re
import threading
import time
from typing import Any
import uuid

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

REPORT_URL = "https://unifiblocker.enerx.ca/api/report.php"
SCHEMA = 1
STORAGE_KEY = "unifiblocker_report"
MAX_BYTES = 8192
_FIRST_DELAY_S = 600          # never during startup
_CHECK_EVERY = timedelta(hours=6)

TOP_KEYS = frozenset({"schema", "install_id", "day", "version", "ha_version", "python",
                      "env", "counts", "usage", "health"})

# Tools counted when used. Read-only polling commands (clients, overview...)
# are not counted; the panel calls those every 30 s.
EVENTS = frozenset({
    "deep_scan_unknowns", "scan_device", "onvif_discover", "onvif_probe",
    "set_category", "clear_category", "check_ip", "block_port", "block_ports",
    "localnet_assign", "localnet_remove", "localnet_ensure_rule", "localnet_range_block",
    "trust", "ignore", "quarantine", "block", "unblock", "reconnect",
    "learned_rule_update", "block_internet", "allow_internet",
})
VIEWS = frozenset({
    "overview", "detail_connected", "detail_wireless", "detail_wired", "detail_blocked",
    "detail_trusted", "detail_threats", "new", "suspicious", "clients", "recommendations",
    "identify", "nas", "localnet", "storage", "mining", "netmap", "category",
    "quarantined", "ports",
    "devices", "cameras", "home", "security", "network", "tools",
})

# Identifier shapes that must never appear in any value (PadSpan's list).
_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:\-.][0-9A-Fa-f]{2}){5}\b|\b[0-9A-Fa-f]{12}\b")
_UUID_RE = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
_HEX32_RE = re.compile(r"\b[0-9A-Fa-f]{32}\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
_ENTITY_RE = re.compile(r"\b[a-z_]{2,}\.[a-z0-9_]{2,}\b")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")


class _State:
    """Everything the report counts between sends. One per HA instance."""

    def __init__(self) -> None:
        self.lock = threading.Lock()   # log records arrive from other threads
        self.enabled = False
        self.usage: dict[str, int] = {}
        self.api_errors: dict[str, int] = {}
        self.log: dict[str, int] = {}
        self.slow_updates = 0
        self.recorder_oversize = 0
        self.polls = 0
        self.poll_failures = 0
        self.poll_ms_total = 0.0
        self.poll_ms_max = 0.0
        self.entity_ids: frozenset[str] = frozenset()

    def take(self) -> dict[str, Any]:
        with self.lock:
            out = {
                "usage": self.usage, "api_errors": self.api_errors, "log": self.log,
                "slow_updates": self.slow_updates, "recorder_oversize": self.recorder_oversize,
                "polls": self.polls, "poll_failures": self.poll_failures,
                "poll_ms_total": self.poll_ms_total, "poll_ms_max": self.poll_ms_max,
            }
            self.reset()
        return out

    def give_back(self, taken: dict[str, Any]) -> None:
        with self.lock:
            for name in ("usage", "api_errors", "log"):
                cur = getattr(self, name)
                for k, v in taken[name].items():
                    cur[k] = cur.get(k, 0) + v
            for name in ("slow_updates", "recorder_oversize", "polls", "poll_failures", "poll_ms_total"):
                setattr(self, name, getattr(self, name) + taken[name])
            self.poll_ms_max = max(self.poll_ms_max, taken["poll_ms_max"])

    def reset(self) -> None:
        self.usage, self.api_errors, self.log = {}, {}, {}
        self.slow_updates = self.recorder_oversize = self.polls = self.poll_failures = 0
        self.poll_ms_total = self.poll_ms_max = 0.0


# Only one UniFi Blocker entry is allowed, and the API client has no hass to
# look things up with, so the counters live at module level.
_state = _State()


def bump(event: str) -> None:
    """Count one use of a tool or view. A no-op unless the report is on."""
    if not _state.enabled or (event not in EVENTS and event.removeprefix("view_") not in VIEWS):
        return
    with _state.lock:
        _state.usage[event] = _state.usage.get(event, 0) + 1


def record_poll(duration_s: float, ok: bool) -> None:
    if not _state.enabled:
        return
    with _state.lock:
        _state.polls += 1
        if not ok:
            _state.poll_failures += 1
        ms = duration_s * 1000
        _state.poll_ms_total += ms
        _state.poll_ms_max = max(_state.poll_ms_max, ms)


def _endpoint(path: str) -> str:
    """'/proxy/network/api/s/default/rest/user/5f3a…?x=1' -> 'rest/user/:id'."""
    path = path.split("?", 1)[0]
    for marker in ("/api/s/", "/api/site/"):
        if marker in path:
            path = path.split(marker, 1)[1].split("/", 1)[-1]   # drop the site name
            break
    else:
        path = path.rsplit("/proxy/network/", 1)[-1].lstrip("/")
    parts = [":id" if (any(c.isdigit() for c in p) or len(p) >= 16) else p
             for p in path.split("/") if p]
    return "/".join(parts)[:40] or "?"


def record_api_error(method: str, path: str, status: int) -> None:
    if not _state.enabled:
        return
    key = f"{method} {_endpoint(path)} {status}"
    with _state.lock:
        _state.api_errors[key] = _state.api_errors.get(key, 0) + 1


class _LogCounter(logging.Handler):
    """Counts our own warnings/errors per module, plus HA's complaints about
    our entities (slow updates, attributes too big for the recorder)."""

    def emit(self, record: logging.LogRecord) -> None:
        if not _state.enabled or record.levelno < logging.WARNING:
            return
        try:
            name = record.name
            if name.startswith("custom_components.unifiblocker"):
                key = f"{name.rsplit('.', 1)[-1]}:{record.levelname}"
                with _state.lock:
                    _state.log[key] = _state.log.get(key, 0) + 1
                return
            msg = record.getMessage()
            if name == "homeassistant.helpers.entity" and "custom_components.unifiblocker" in msg:
                with _state.lock:
                    _state.slow_updates += 1
            elif name == "homeassistant.components.recorder.db_schema" and "exceed maximum size" in msg:
                if any(eid in msg for eid in _state.entity_ids):
                    with _state.lock:
                        _state.recorder_oversize += 1
        except Exception:  # a log handler must never raise
            pass


_HANDLER = _LogCounter()
_WATCHED_LOGGERS = ("custom_components.unifiblocker", "homeassistant.helpers.entity",
                    "homeassistant.components.recorder.db_schema")


# ── payload ──────────────────────────────────────────────────────────────

def _major_minor(version: str) -> str:
    # A four-part version would look like an IPv4 address and get the whole
    # report refused, so keep two parts.
    return ".".join(str(version or "").split(".")[:2])[:16]


def build_payload(hass: HomeAssistant, install_id: str, taken: dict[str, Any] | None = None) -> dict[str, Any]:
    """The report as it would go now. Pass *taken* to report those counters;
    without it the live counters are read but not reset (Preview)."""
    from homeassistant.const import __version__ as ha_version  # noqa: PLC0415

    from .config_flow import DEFAULT_LOCAL_CIDR  # noqa: PLC0415
    from .recommendations import find_advisory  # noqa: PLC0415

    if taken is None:
        with _state.lock:
            taken = {
                "usage": dict(_state.usage), "api_errors": dict(_state.api_errors),
                "log": dict(_state.log), "slow_updates": _state.slow_updates,
                "recorder_oversize": _state.recorder_oversize, "polls": _state.polls,
                "poll_failures": _state.poll_failures, "poll_ms_total": _state.poll_ms_total,
                "poll_ms_max": _state.poll_ms_max,
            }

    entry_data = next((d for d in hass.data.get(DOMAIN, {}).values()
                       if isinstance(d, dict) and "coordinator" in d), None)
    env: dict[str, Any] = {}
    counts: dict[str, Any] = {}
    if entry_data:
        coord = entry_data["coordinator"]
        data = coord.data
        entry = coord.config_entry
        opts = {**entry.data, **entry.options} if entry else {}
        env = {
            "scan_interval": int(opts.get("scan_interval", 60)),
            "auto_scan_count": int(opts.get("auto_scan_count", 5)),
            "local_cidr_default": opts.get("local_cidr", DEFAULT_LOCAL_CIDR) == DEFAULT_LOCAL_CIDR,
            "verify_ssl": bool(opts.get("verify_ssl", False)),
        }
        from .licence import licence_of  # noqa: PLC0415
        lic = licence_of(hass)
        lst = lic.state() if lic else {}
        env["edition"] = "trial" if lst.get("trial") and lst.get("pro") else "pro" if lst.get("pro") else "free"
        if data:
            env["controller_version"] = _major_minor(data.health.get("version", ""))
            env["controller_ok"] = bool(data.health.get("connection_ok"))
            cats: dict[str, int] = {}
            advisories: dict[str, int] = {}
            cameras = 0
            vuln = {"affected": 0, "check": 0, "old_firmware": 0}
            for c in data.clients:
                cat = data.categories.get(c.get("mac", "").lower(), {}).get("category", "unknown")
                cats[cat] = cats.get(cat, 0) + 1
                e = data.enrich_client(c)
                cameras += bool(e.get("is_camera"))
                v = e.get("vulns") or {}
                found = find_advisory(e.get("vendor", ""), e.get("onvif_manufacturer", ""), v.get("family") or "")
                if found:
                    advisories[found[0]] = advisories.get(found[0], 0) + 1
                if v.get("worst") in ("affected", "likely"):
                    vuln["affected"] += 1
                elif v.get("worst") == "check":
                    vuln["check"] += 1
                if (v.get("firmware_age_years") or 0) >= 5:
                    vuln["old_firmware"] += 1
            local_net = entry_data.get("local_net")
            scanner = entry_data.get("scanner")
            learned = entry_data.get("learned")
            store = entry_data["store"]
            counts = {
                "clients": data.total_clients,
                "wired": sum(1 for c in data.clients if c.get("is_wired")),
                "cameras": cameras,
                "suspicious": data.suspicious_count,
                "new": data.new_count,
                "trusted": data.trusted_count,
                "quarantined": len(data.quarantined_macs),
                "blocked": data.blocked_count,
                "local_only": len(local_net.assignments) if local_net else 0,
                "miners": len(data.miners),
                "scanned": len(scanner.cache) if scanner else 0,
                "manual_categories": len(store.get_all_manual_categories()),
                "learned_rules": sum(len(getattr(learned, a, None) or ()) for a in (
                    "_vendor_rules", "_hostname_rules", "_mac_rules", "_port_rules")) if learned else 0,
                "categories": cats,
                "advisories": advisories,
                "vulnerable": vuln,
                "insights": {
                    "security_events_24h": len(data.threat_events),
                    "local_only_blocks_24h": sum(1 for e in data.security if e.get("ours")),
                    "own_camera_hotspots": sum(1 for h in data.hotspots if h["reason"] == "own_camera"),
                    "camera_ssids_nearby": sum(1 for h in data.hotspots if h["reason"] == "camera_ssid"),
                    "traffic_spikes": sum(1 for c in data.clients if (data.enrich_client(c).get("traffic_spike"))),
                    "unifi_fingerprint_cameras": sum(1 for c in data.clients if c.get("dev_cat") in (9, 57)),
                    "containment": dict(collections.Counter(
                        data.enrich_client(c).get("containment") for c in data.clients
                        if data.enrich_client(c).get("containment"))),
                    "dns_bypass_devices": sum(1 for s in data.phone_home.values() if s.get("dns_bypass")),
                    "home_automation_tiers": dict(collections.Counter(
                        (data.enrich_client(c).get("home_automation") or {}).get("tier") for c in data.clients
                        if data.enrich_client(c).get("home_automation"))),
                    "phone_home_clouds": dict(collections.Counter(
                        cloud for s in data.phone_home.values() for cloud in s.get("clouds", {}))),
                },
            }

    polls = taken["polls"]
    return {
        "schema": SCHEMA,
        "install_id": install_id,
        "day": time.strftime("%Y-%m-%d", time.gmtime()),
        "version": _version,
        "ha_version": str(ha_version)[:16],
        "python": platform.python_version().rsplit(".", 1)[0],
        "env": env,
        "counts": counts,
        "usage": taken["usage"],
        "health": {
            "polls": polls,
            "poll_failures": taken["poll_failures"],
            "poll_ms_avg": round(taken["poll_ms_total"] / polls) if polls else None,
            "poll_ms_max": round(taken["poll_ms_max"]),
            "api_errors": taken["api_errors"],
            "log": taken["log"],
            "slow_updates": taken["slow_updates"],
            "recorder_oversize": taken["recorder_oversize"],
        },
    }


# Filled in by ReportManager.async_load from HA's (cached) integration info;
# reading manifest.json here would be blocking I/O on the event loop.
_version = "?"


def assert_shareable(payload: dict[str, Any]) -> None:
    """Refuse a report that carries anything identifier-shaped."""
    if not isinstance(payload, dict):
        raise ValueError("payload is not a dict")
    extra = set(payload) - TOP_KEYS
    if extra:
        raise ValueError(f"unexpected top-level keys: {sorted(extra)}")

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(str(k), path + "." + str(k) + "<key>")
                walk(v, path + "." + str(k))
        elif isinstance(node, (list, tuple)):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            if path == ".install_id":
                if node and not _UUID_RE.fullmatch(node):
                    raise ValueError("install_id is not a UUID")
                return
            for name, rx in (("UUID", _UUID_RE), ("32-hex", _HEX32_RE), ("MAC address", _MAC_RE),
                             ("IP address", _IPV4_RE), ("IPv6 address", _IPV6_RE),
                             ("email address", _EMAIL_RE), ("entity id", _ENTITY_RE)):
                if rx.search(node):
                    raise ValueError(f"{name} in {path}")
            if len(node) > 64:
                raise ValueError(f"string too long in {path}")
        elif node is None or isinstance(node, (bool, int, float)):
            return
        else:
            raise ValueError(f"unexpected value type {type(node).__name__} in {path}")

    walk(payload, "")
    if len(json.dumps(payload)) > MAX_BYTES:
        raise ValueError("payload too large")


# ── settings, sending, scheduling ────────────────────────────────────────

class ReportManager:
    """Consent, install id, last-sent day, and the daily send."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._store = Store(hass, 1, STORAGE_KEY)
        self.settings: dict[str, Any] = {"enabled": False, "install_id": "", "last_day": ""}
        self._unsubs: list[Any] = []

    async def async_load(self) -> None:
        data = await self._store.async_load()
        if isinstance(data, dict):
            self.settings.update(data)
        _state.enabled = bool(self.settings["enabled"])
        global _version  # noqa: PLW0603
        try:
            from homeassistant.loader import async_get_integration  # noqa: PLC0415
            _version = str((await async_get_integration(self.hass, DOMAIN)).version or "?")
        except Exception:
            _version = "?"

    async def _save(self) -> None:
        await self._store.async_save(self.settings)

    def refresh_entity_ids(self, entry_id: str) -> None:
        from homeassistant.helpers import entity_registry as er  # noqa: PLC0415
        reg = er.async_get(self.hass)
        _state.entity_ids = frozenset(e.entity_id for e in er.async_entries_for_config_entry(reg, entry_id))

    async def set_enabled(self, on: bool) -> None:
        if on and not self.settings["enabled"]:
            with _state.lock:
                _state.reset()      # the first report holds nothing from before the yes
            if not _UUID_RE.fullmatch(self.settings.get("install_id") or ""):
                self.settings["install_id"] = str(uuid.uuid4())
        self.settings["enabled"] = bool(on)
        _state.enabled = bool(on)
        await self._save()

    async def new_install_id(self) -> str:
        self.settings["install_id"] = str(uuid.uuid4())
        await self._save()
        return self.settings["install_id"]

    def preview(self) -> dict[str, Any]:
        payload = build_payload(self.hass, self.settings.get("install_id") or "")
        problems: list[str] = []
        try:
            assert_shareable(payload)
        except ValueError as err:
            problems.append(str(err))
        return {"payload": payload, "problems": problems, "url": REPORT_URL,
                "bytes": len(json.dumps(payload))}

    async def send_now(self, *, force: bool = False) -> dict[str, Any]:
        if not self.settings["enabled"]:
            return {"sent": False, "reason": "disabled"}
        today = time.strftime("%Y-%m-%d", time.gmtime())
        if not force and self.settings.get("last_day") == today:
            return {"sent": False, "reason": "already sent today"}
        taken = _state.take()
        try:
            payload = build_payload(self.hass, self.settings["install_id"], taken)
            assert_shareable(payload)
        except ValueError as err:
            _state.give_back(taken)
            _LOGGER.error("Usage report refused before sending: %s", err)
            return {"sent": False, "reason": f"refused: {err}"}
        body = json.dumps(payload).encode()
        try:
            from homeassistant.helpers.aiohttp_client import async_get_clientsession  # noqa: PLC0415
            session = async_get_clientsession(self.hass)
            async with session.post(REPORT_URL, data=body, timeout=15,
                                    headers={"Content-Type": "application/json"}) as resp:
                if not 200 <= resp.status < 300:
                    _state.give_back(taken)
                    _LOGGER.debug("Usage report HTTP %s", resp.status)
                    return {"sent": False, "reason": f"http {resp.status}", "bytes": len(body)}
        except Exception as err:  # offline, DNS, timeout: try again next time
            _state.give_back(taken)
            _LOGGER.debug("Usage report not sent: %s", err)
            return {"sent": False, "reason": "network", "bytes": len(body)}
        self.settings["last_day"] = today
        await self._save()
        return {"sent": True, "reason": "", "bytes": len(body)}

    def start(self) -> None:
        from homeassistant.helpers.event import async_call_later, async_track_time_interval  # noqa: PLC0415

        for name in _WATCHED_LOGGERS:
            logging.getLogger(name).addHandler(_HANDLER)

        async def _run(_now: Any = None) -> None:
            if self.settings["enabled"]:
                await self.send_now()

        self._unsubs = [
            async_call_later(self.hass, _FIRST_DELAY_S, _run),
            async_track_time_interval(self.hass, _run, _CHECK_EVERY),
        ]

    def stop(self) -> None:
        for unsub in self._unsubs:
            unsub()
        self._unsubs = []
        for name in _WATCHED_LOGGERS:
            logging.getLogger(name).removeHandler(_HANDLER)


# ── websocket ────────────────────────────────────────────────────────────

def _manager(hass: HomeAssistant) -> ReportManager | None:
    for d in hass.data.get(DOMAIN, {}).values():
        if isinstance(d, dict) and isinstance(d.get("report"), ReportManager):
            return d["report"]
    return None


def _status(mgr: ReportManager) -> dict[str, Any]:
    return {"enabled": bool(mgr.settings["enabled"]), "has_id": bool(mgr.settings.get("install_id")),
            "last_day": mgr.settings.get("last_day") or "", "url": REPORT_URL}


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "unifiblocker/report_status"})
@websocket_api.async_response
async def ws_report_status(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    mgr = _manager(hass)
    if not mgr:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    connection.send_result(msg["id"], _status(mgr))


@websocket_api.require_admin
@websocket_api.websocket_command({
    vol.Required("type"): "unifiblocker/report_set",
    vol.Required("enabled"): bool,
})
@websocket_api.async_response
async def ws_report_set(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    mgr = _manager(hass)
    if not mgr:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    await mgr.set_enabled(msg["enabled"])
    connection.send_result(msg["id"], _status(mgr))


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "unifiblocker/report_preview"})
@websocket_api.async_response
async def ws_report_preview(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    mgr = _manager(hass)
    if not mgr:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    connection.send_result(msg["id"], mgr.preview())


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "unifiblocker/report_send"})
@websocket_api.async_response
async def ws_report_send(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    mgr = _manager(hass)
    if not mgr:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    result = await mgr.send_now(force=True)
    connection.send_result(msg["id"], {**result, **_status(mgr)})


@websocket_api.require_admin
@websocket_api.websocket_command({vol.Required("type"): "unifiblocker/report_new_id"})
@websocket_api.async_response
async def ws_report_new_id(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    mgr = _manager(hass)
    if not mgr:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    await mgr.new_install_id()
    connection.send_result(msg["id"], _status(mgr))


@websocket_api.require_admin
@websocket_api.websocket_command({
    vol.Required("type"): "unifiblocker/report_view",
    vol.Required("view"): str,
})
@callback
def ws_report_view(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> None:
    bump(f"view_{msg['view']}")
    connection.send_result(msg["id"], {"ok": True})


def counted(handler: Any) -> Any:
    """Wrap a websocket handler so using it counts toward the report.

    functools.wraps copies the _ws_command/_ws_schema attributes HA reads at
    registration, so the wrapped handler registers like the original."""
    event = str(getattr(handler, "_ws_command", "")).removeprefix(f"{DOMAIN}/")
    if event not in EVENTS:
        return handler

    @functools.wraps(handler)
    def wrapper(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict) -> Any:
        bump(event)
        return handler(hass, connection, msg)

    return wrapper


WS_COMMANDS = (ws_report_status, ws_report_set, ws_report_preview, ws_report_send,
               ws_report_new_id, ws_report_view)
