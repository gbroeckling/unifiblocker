"""WebSocket API for the UniFi Blocker frontend panel."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN, STATE_IGNORED, STATE_QUARANTINED, STATE_TRUSTED

_LOGGER = logging.getLogger(__name__)


def async_register_websocket_commands(hass: HomeAssistant) -> None:
    """Register all WebSocket command handlers."""
    websocket_api.async_register_command(hass, ws_get_clients)
    websocket_api.async_register_command(hass, ws_get_overview)
    websocket_api.async_register_command(hass, ws_get_categories)
    websocket_api.async_register_command(hass, ws_get_category_clients)
    websocket_api.async_register_command(hass, ws_set_category)
    websocket_api.async_register_command(hass, ws_trust_device)
    websocket_api.async_register_command(hass, ws_ignore_device)
    websocket_api.async_register_command(hass, ws_quarantine_device)
    websocket_api.async_register_command(hass, ws_block_device)
    websocket_api.async_register_command(hass, ws_unblock_device)
    websocket_api.async_register_command(hass, ws_reconnect_device)
    _LOGGER.debug("WebSocket commands registered")


def _get_coordinator(hass: HomeAssistant):
    """Return the first active coordinator."""
    for _eid, edata in hass.data.get(DOMAIN, {}).items():
        if isinstance(edata, dict) and "coordinator" in edata:
            return edata
    return None


# ── Read-only commands ───────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/clients"}
)
@websocket_api.async_response
async def ws_get_clients(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return all connected clients with enriched data."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"clients": []})
        return

    data = entry["coordinator"].data
    clients = data.all_clients_enriched()
    connection.send_result(msg["id"], {"clients": clients})


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/overview"}
)
@websocket_api.async_response
async def ws_get_overview(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return dashboard overview counts and health."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {})
        return

    data = entry["coordinator"].data
    from .device_categorizer import CATEGORY_LABELS, CATEGORY_ICONS
    connection.send_result(msg["id"], {
        "total_clients": data.total_clients,
        "new_count": data.new_count,
        "suspicious_count": data.suspicious_count,
        "blocked_count": data.blocked_count,
        "quarantined_count": len(data.quarantined_macs),
        "trusted_count": data.trusted_count,
        "ignored_count": data.ignored_count,
        "wireless_count": sum(1 for c in data.clients if not c.get("is_wired", False)),
        "wired_count": sum(1 for c in data.clients if c.get("is_wired", False)),
        "threat_events": len(data.threat_events),
        "health": data.health,
        "new_devices": [data.enrich_client(c) for c in data.new_devices],
        "suspicious_devices": [
            data.enrich_client(c) for c in data.suspicious_clients
        ],
        "category_counts": data.category_counts,
        "category_labels": CATEGORY_LABELS,
        "category_icons": CATEGORY_ICONS,
    })


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/categories"}
)
@websocket_api.async_response
async def ws_get_categories(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return category counts and metadata."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"categories": {}})
        return

    from .device_categorizer import CATEGORY_LABELS, CATEGORY_ICONS
    data = entry["coordinator"].data
    counts = data.category_counts
    result = {}
    for cat, count in sorted(counts.items(), key=lambda x: -x[1]):
        result[cat] = {
            "count": count,
            "label": CATEGORY_LABELS.get(cat, cat),
            "icon": CATEGORY_ICONS.get(cat, "❓"),
            "show_in_sidebar": count >= 5,
        }
    connection.send_result(msg["id"], {"categories": result})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/category_clients",
        vol.Required("category"): str,
    }
)
@websocket_api.async_response
async def ws_get_category_clients(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return enriched clients for a specific category."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"clients": []})
        return

    data = entry["coordinator"].data
    cat_clients = data.clients_by_category(msg["category"])
    enriched = [data.enrich_client(c) for c in cat_clients]
    connection.send_result(msg["id"], {"clients": enriched, "category": msg["category"]})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/set_category",
        vol.Required("mac"): str,
        vol.Required("category"): str,
        vol.Optional("name"): str,
    }
)
@websocket_api.async_response
async def ws_set_category(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Manually set a device's category."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return

    from .device_categorizer import CATEGORY_LABELS
    cat = msg["category"]
    if cat not in CATEGORY_LABELS:
        connection.send_error(msg["id"], "invalid_category", f"Unknown category: {cat}")
        return

    mac = msg["mac"]
    name = msg.get("name")
    await entry["store"].set_manual_category(mac, cat, name=name)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac, "category": cat})


# ── Write commands (require action mode) ─────────────────────────────


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/trust",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_trust_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Trust a device and unblock it."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["store"].set_state(mac, STATE_TRUSTED)
    await entry["api"].unblock_client(mac)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac, "state": "trusted"})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/ignore",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_ignore_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Ignore a device."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["store"].set_state(mac, STATE_IGNORED)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac, "state": "ignored"})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/quarantine",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_quarantine_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Quarantine and block a device."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["store"].set_state(mac, STATE_QUARANTINED)
    await entry["api"].block_client(mac)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac, "state": "quarantined"})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/block",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_block_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Block a device on the controller."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["api"].block_client(mac)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/unblock",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_unblock_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Unblock a device on the controller."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["api"].unblock_client(mac)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac})


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/reconnect",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_reconnect_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Force-reconnect a device."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Integration not loaded")
        return
    mac = msg["mac"]
    await entry["api"].reconnect_client(mac)
    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {"ok": True, "mac": mac})
