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
    websocket_api.async_register_command(hass, ws_localnet_status)
    websocket_api.async_register_command(hass, ws_localnet_assign)
    websocket_api.async_register_command(hass, ws_localnet_remove)
    websocket_api.async_register_command(hass, ws_localnet_ensure_rule)
    websocket_api.async_register_command(hass, ws_get_recommendations)
    websocket_api.async_register_command(hass, ws_scan_device)
    websocket_api.async_register_command(hass, ws_scan_results)
    websocket_api.async_register_command(hass, ws_block_port)
    websocket_api.async_register_command(hass, ws_block_ports)
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


# ── Recommendations ──────────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/recommendations"}
)
@websocket_api.async_response
async def ws_get_recommendations(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return security recommendations for all devices + network-wide."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"device_recs": {}, "network_recs": []})
        return

    from .recommendations import generate_recommendations, generate_network_recommendations

    data = entry["coordinator"].data
    scanner = entry.get("scanner")
    local_net = entry.get("local_net")

    # Per-device recommendations.
    device_recs: dict[str, list] = {}
    for client in data.clients:
        enriched = data.enrich_client(client)
        mac = enriched.get("mac", "").lower()
        # Attach scan results if available.
        if scanner:
            scan = scanner.get_result(mac)
            if scan:
                enriched["scan_result"] = scan
        recs = generate_recommendations(enriched)
        if recs:
            device_recs[mac] = recs

    # Network-wide recommendations.
    fw_exists = False
    if local_net:
        fw_status = await local_net.get_firewall_status(entry["api"])
        fw_exists = fw_status.get("exists", False)

    all_enriched = data.all_clients_enriched()
    if scanner:
        for d in all_enriched:
            scan = scanner.get_result(d.get("mac", "").lower())
            if scan:
                d["scan_result"] = scan

    network_recs = generate_network_recommendations(all_enriched, firewall_exists=fw_exists)

    connection.send_result(msg["id"], {
        "device_recs": device_recs,
        "network_recs": network_recs,
        "total_device_recs": sum(len(r) for r in device_recs.values()),
        "critical_count": sum(1 for recs in device_recs.values() for r in recs if r["priority"] == "critical"),
        "high_count": sum(1 for recs in device_recs.values() for r in recs if r["priority"] == "high"),
    })


# ── Port scanner commands ─────────────────────────────────────────────


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/scan_device",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_scan_device(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Trigger a port scan on a specific device."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return

    scanner = entry.get("scanner")
    if not scanner:
        connection.send_error(msg["id"], "no_scanner", "Port scanner not available")
        return

    # Find the device's IP.
    data = entry["coordinator"].data
    if not data:
        connection.send_error(msg["id"], "no_data", "No client data")
        return

    client = data.client_by_mac(msg["mac"])
    if not client:
        connection.send_error(msg["id"], "not_found", f"Device {msg['mac']} not found")
        return

    ip = client.get("ip", "")
    if not ip:
        connection.send_error(msg["id"], "no_ip", "Device has no IP address")
        return

    result = await scanner.scan_device(ip, msg["mac"])
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/scan_results"}
)
@websocket_api.async_response
async def ws_scan_results(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return all cached scan results."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("scanner"):
        connection.send_result(msg["id"], {"results": {}})
        return

    connection.send_result(msg["id"], {"results": entry["scanner"].cache})


# ── Per-MAC port blocking ─────────────────────────────────────────────


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/block_port",
        vol.Required("mac"): str,
        vol.Required("port"): int,
        vol.Optional("protocol", default="tcp"): str,
    }
)
@websocket_api.async_response
async def ws_block_port(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Block a single port for a specific device."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    try:
        result = await entry["api"].block_port_for_mac(
            msg["mac"], msg["port"], protocol=msg.get("protocol", "tcp")
        )
        connection.send_result(msg["id"], {"ok": True, "mac": msg["mac"], "port": msg["port"]})
    except Exception as err:
        connection.send_error(msg["id"], "failed", str(err))


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/block_ports",
        vol.Required("mac"): str,
        vol.Required("ports"): [int],
        vol.Optional("protocol", default="tcp"): str,
    }
)
@websocket_api.async_response
async def ws_block_ports(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Block multiple ports for a specific device in one rule."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return
    try:
        result = await entry["api"].block_ports_for_mac(
            msg["mac"], msg["ports"], protocol=msg.get("protocol", "tcp")
        )
        connection.send_result(msg["id"], {"ok": True, "mac": msg["mac"], "ports": msg["ports"]})
    except Exception as err:
        connection.send_error(msg["id"], "failed", str(err))


# ── Local network commands ────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/localnet_status"}
)
@websocket_api.async_response
async def ws_localnet_status(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return local-network assignments, IP ranges, and firewall status."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_result(msg["id"], {})
        return

    local_net = entry.get("local_net")
    if not local_net:
        connection.send_result(msg["id"], {"error": "Local network manager not loaded"})
        return

    fw_status = await local_net.get_firewall_status(entry["api"])

    connection.send_result(msg["id"], {
        "assignments": local_net.assignments,
        "ranges": local_net.get_range_info(),
        "firewall": fw_status,
        "subnet": "192.168.2.0/24",
    })


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/localnet_assign",
        vol.Required("mac"): str,
        vol.Required("category"): str,
        vol.Optional("name"): str,
    }
)
@websocket_api.async_response
async def ws_localnet_assign(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Assign a device to the local-only subnet."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("local_net"):
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return

    result = await entry["local_net"].assign_local_ip(
        entry["api"], msg["mac"], msg["category"], msg.get("name", "")
    )
    if result.get("ok"):
        await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/localnet_remove",
        vol.Required("mac"): str,
    }
)
@websocket_api.async_response
async def ws_localnet_remove(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Remove a device from the local-only subnet."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("local_net"):
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return

    result = await entry["local_net"].remove_assignment(entry["api"], msg["mac"])
    if result.get("ok"):
        await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/localnet_ensure_rule"}
)
@websocket_api.async_response
async def ws_localnet_ensure_rule(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Create or verify the WAN-block firewall rule."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("local_net"):
        connection.send_error(msg["id"], "not_ready", "Not loaded")
        return

    result = await entry["local_net"].ensure_firewall_rule(entry["api"])
    connection.send_result(msg["id"], result)


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
