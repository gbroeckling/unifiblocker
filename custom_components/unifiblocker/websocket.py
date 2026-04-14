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
    websocket_api.async_register_command(hass, ws_get_learned)
    websocket_api.async_register_command(hass, ws_get_suggestions)
    websocket_api.async_register_command(hass, ws_localnet_status)
    websocket_api.async_register_command(hass, ws_localnet_assign)
    websocket_api.async_register_command(hass, ws_localnet_remove)
    websocket_api.async_register_command(hass, ws_localnet_ensure_rule)
    websocket_api.async_register_command(hass, ws_onvif_discover)
    websocket_api.async_register_command(hass, ws_onvif_probe)
    websocket_api.async_register_command(hass, ws_onvif_results)
    websocket_api.async_register_command(hass, ws_get_recommendations)
    websocket_api.async_register_command(hass, ws_deep_scan_unknowns)
    websocket_api.async_register_command(hass, ws_scan_device)
    websocket_api.async_register_command(hass, ws_scan_results)
    websocket_api.async_register_command(hass, ws_block_port)
    websocket_api.async_register_command(hass, ws_block_ports)
    websocket_api.async_register_command(hass, ws_firewall_rules_debug)
    websocket_api.async_register_command(hass, ws_traffic_rules_debug)
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
    try:
        clients = data.all_clients_enriched()
    except Exception as err:
        _LOGGER.error("Failed to enrich clients: %s", err, exc_info=True)
        clients = []

    # If enrichment returned nothing or crashed, build basic list.
    if not clients and data.clients:
        from .vendor_lookup import lookup_vendor_safe
        for c in data.clients:
            mac = c.get("mac", "")
            mac_lower = mac.lower()
            cat_data = data.categories.get(mac_lower, {})
            clients.append({
                "mac": mac,
                "name": c.get("name") or c.get("hostname") or "",
                "hostname": c.get("hostname", ""),
                "ip": c.get("ip", ""),
                "vendor": c.get("oui") or lookup_vendor_safe(mac),
                "blocked": c.get("blocked", False),
                "wired": c.get("is_wired", False),
                "rssi": c.get("rssi"),
                "essid": c.get("essid", ""),
                "tx_bytes": c.get("tx_bytes"),
                "rx_bytes": c.get("rx_bytes"),
                "state": data.store.get_state(mac),
                "category": cat_data.get("category", "unknown"),
                "category_label": cat_data.get("category_label", "Unknown"),
                "category_icon": cat_data.get("category_icon", "❓"),
                "confidence": cat_data.get("confidence", "low"),
                "suspicious": False,
                "threat_level": "none",
                "suspicion_score": 0,
                "suspicion_flags": [],
                "is_camera": cat_data.get("category") == "camera",
                "ip_history": data.store.get_ip_history(mac),
            })
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

    # Build client dicts WITHOUT full enrichment (which can crash).
    # Use raw UniFi data + category info from the categorizer directly.
    from .vendor_lookup import lookup_vendor_safe
    clients = []
    for c in cat_clients:
        mac = c.get("mac", "")
        mac_lower = mac.lower()
        cat_data = data.categories.get(mac_lower, {})
        clients.append({
            "mac": mac,
            "name": c.get("name") or c.get("hostname") or "",
            "hostname": c.get("hostname", ""),
            "ip": c.get("ip", ""),
            "vendor": c.get("oui") or lookup_vendor_safe(mac),
            "blocked": c.get("blocked", False),
            "wired": c.get("is_wired", False),
            "rssi": c.get("rssi"),
            "essid": c.get("essid", ""),
            "tx_bytes": c.get("tx_bytes"),
            "rx_bytes": c.get("rx_bytes"),
            "state": data.store.get_state(mac),
            "category": cat_data.get("category", "unknown"),
            "category_label": cat_data.get("category_label", "Unknown"),
            "category_icon": cat_data.get("category_icon", "❓"),
            "confidence": cat_data.get("confidence", "low"),
            "source": cat_data.get("source", "none"),
            "suspicious": False,
            "threat_level": "none",
            "suspicion_score": 0,
            "suspicion_flags": [],
            "is_camera": cat_data.get("category") == "camera",
            "onvif_manufacturer": cat_data.get("onvif_manufacturer", ""),
            "onvif_model": cat_data.get("onvif_model", ""),
        })
    connection.send_result(msg["id"], {"clients": clients, "category": msg["category"]})


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

    # Learn from this manual categorization.
    learned_result = {}
    learned = entry.get("learned")
    if learned:
        # Get the device's details for learning.
        data = entry["coordinator"].data
        client = data.client_by_mac(mac) if data else None
        scan = entry.get("scanner")
        scan_result = scan.get_result(mac.lower()) if scan else None

        learned_result = await learned.learn_from_device(
            cat,
            mac=mac,
            vendor=client.get("oui", "") if client else "",
            hostname=client.get("hostname") or (client.get("name", "") if client else ""),
            open_ports=scan_result.get("open_ports") if scan_result else None,
        )

    await entry["coordinator"].async_request_refresh()
    connection.send_result(msg["id"], {
        "ok": True, "mac": mac, "category": cat,
        "learned": learned_result,
    })


# ── Learning engine ──────────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/learned_rules"}
)
@websocket_api.async_response
async def ws_get_learned(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return all learned pattern rules."""
    entry = _get_coordinator(hass)
    learned = entry.get("learned") if entry else None
    if not learned:
        connection.send_result(msg["id"], {"rules": {}, "total_rules": 0})
        return
    connection.send_result(msg["id"], learned.rules_summary)


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/suggestions"}
)
@websocket_api.async_response
async def ws_get_suggestions(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return uncategorized devices that match learned patterns."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("learned") or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"suggestions": []})
        return

    from .vendor_lookup import lookup_vendor_safe
    data = entry["coordinator"].data
    scanner = entry.get("scanner")

    # Build basic device info for matching.
    devices = []
    for c in data.clients:
        mac = c.get("mac", "").lower()
        cat_data = data.categories.get(mac, {})
        scan_data = scanner.get_result(mac) if scanner else None
        devices.append({
            "mac": c.get("mac", ""),
            "name": c.get("name") or c.get("hostname") or "",
            "hostname": c.get("hostname", ""),
            "ip": c.get("ip", ""),
            "vendor": c.get("oui") or lookup_vendor_safe(c.get("mac", "")),
            "category": cat_data.get("category", "unknown"),
            "scan_result": scan_data or {},
        })

    suggestions = entry["learned"].get_suggestions(devices)
    connection.send_result(msg["id"], {
        "suggestions": suggestions,
        "count": len(suggestions),
    })


# ── ONVIF discovery & probe ───────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/onvif_discover"}
)
@websocket_api.async_response
async def ws_onvif_discover(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Run ONVIF WS-Discovery and probe all found cameras."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("onvif"):
        connection.send_error(msg["id"], "not_ready", "ONVIF probe not available")
        return
    results = await entry["onvif"].discover_and_probe_all()
    connection.send_result(msg["id"], {
        "count": len(results),
        "devices": results,
    })


@websocket_api.websocket_command(
    {
        vol.Required("type"): "unifiblocker/onvif_probe",
        vol.Required("ip"): str,
    }
)
@websocket_api.async_response
async def ws_onvif_probe(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Probe a single IP for ONVIF device information."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("onvif"):
        connection.send_error(msg["id"], "not_ready", "ONVIF probe not available")
        return
    result = await entry["onvif"].probe_ip(msg["ip"])
    connection.send_result(msg["id"], result)


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/onvif_results"}
)
@websocket_api.async_response
async def ws_onvif_results(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return all cached ONVIF probe results."""
    entry = _get_coordinator(hass)
    if not entry or not entry.get("onvif"):
        connection.send_result(msg["id"], {"results": {}, "discovered": []})
        return
    onvif = entry["onvif"]
    connection.send_result(msg["id"], {
        "results": onvif.cache,
        "discovered": onvif.discovered_devices,
    })


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


# ── Deep scan (Quantify) ─────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/deep_scan_unknowns"}
)
@websocket_api.async_response
async def ws_deep_scan_unknowns(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Deep-scan all unknown/uncategorized devices using multiple techniques."""
    entry = _get_coordinator(hass)
    if not entry or not entry["coordinator"].data:
        connection.send_result(msg["id"], {"scanned": 0, "identified": 0})
        return

    from .deep_scan import deep_scan_multiple
    from .vendor_lookup import lookup_vendor_safe

    data = entry["coordinator"].data
    store = entry["store"]
    learned = entry.get("learned")

    # Find all unknown devices with IPs.
    targets = []
    scanner = entry.get("scanner")

    for c in data.clients:
        mac = c.get("mac", "").lower()
        ip = c.get("ip", "")
        cat = data.categories.get(mac, {}).get("category", "unknown")
        if ip and cat == "unknown":
            # Pass all available UniFi data to give the scanner more context.
            scan_result = scanner.get_result(mac) if scanner else None
            targets.append({
                "ip": ip, "mac": mac,
                "vendor": c.get("oui") or lookup_vendor_safe(mac),
                "hostname": c.get("hostname") or c.get("name") or "",
                "is_wired": c.get("is_wired", False),
                "open_ports": scan_result.get("open_ports", []) if scan_result else [],
            })

    _LOGGER.info("Quantify: deep-scanning %d unknown devices", len(targets))

    # Run deep scan.
    results = await deep_scan_multiple(targets)

    # Apply results — set categories for identified devices.
    identified = 0
    for mac, result in results.items():
        best = result.get("best_guess", "unknown")
        if best != "unknown":
            await store.set_manual_category(mac, best)
            identified += 1

            # Also teach the learning engine.
            if learned:
                client = data.client_by_mac(mac)
                vendor = client.get("oui") or lookup_vendor_safe(mac) if client else ""
                hostname = client.get("hostname", "") if client else ""
                await learned.learn_from_device(
                    best, mac=mac, vendor=vendor, hostname=hostname,
                )

    if identified:
        await entry["coordinator"].async_request_refresh()

    connection.send_result(msg["id"], {
        "scanned": len(results),
        "identified": identified,
        "results": {mac: {
            "best_guess": r.get("best_guess", "unknown"),
            "best_description": r.get("best_description", ""),
            "techniques_used": list(r.get("techniques", {}).keys()),
        } for mac, r in results.items()},
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
        entry["api"], msg["mac"], msg["category"], msg.get("name", ""),
        store=entry.get("store"),
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


# ── Firewall debug ───────────────────────────────────────────────────


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/firewall_rules_debug"}
)
@websocket_api.async_response
async def ws_firewall_rules_debug(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return existing firewall rules for diagnostic purposes (read-only)."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_result(msg["id"], {"rules": []})
        return
    try:
        rules = await entry["api"].get_firewall_rules()
        # Only return safe fields — no credentials or sensitive data.
        safe_rules = [
            {
                "_id": r.get("_id", ""),
                "name": r.get("name", ""),
                "enabled": r.get("enabled"),
                "action": r.get("action", ""),
                "ruleset": r.get("ruleset", ""),
                "protocol": r.get("protocol", ""),
                "src_address": r.get("src_address", ""),
                "dst_address": r.get("dst_address", ""),
                "dst_port": r.get("dst_port", ""),
                "src_mac_address": r.get("src_mac_address", ""),
                "rule_index": r.get("rule_index"),
                "site_id": r.get("site_id", ""),
            }
            for r in rules
        ]
        connection.send_result(msg["id"], {"rules": safe_rules, "count": len(rules)})
    except Exception as err:
        connection.send_result(msg["id"], {"rules": [], "error": str(err)})


@websocket_api.websocket_command(
    {vol.Required("type"): "unifiblocker/traffic_rules_debug"}
)
@websocket_api.async_response
async def ws_traffic_rules_debug(
    hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict
) -> None:
    """Return existing v2 traffic rules for diagnostics."""
    entry = _get_coordinator(hass)
    if not entry:
        connection.send_result(msg["id"], {"rules": [], "error": "not loaded"})
        return
    try:
        rules = await entry["api"].get_traffic_rules()
        connection.send_result(msg["id"], {"rules": rules, "count": len(rules)})
    except Exception as err:
        # Also try to get the raw response for debugging
        connection.send_result(msg["id"], {"rules": [], "error": str(err)})


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
