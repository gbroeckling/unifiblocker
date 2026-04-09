"""UniFi Blocker – network device review & quarantine for Home Assistant."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SITE,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    PLATFORMS,
    STATE_IGNORED,
    STATE_QUARANTINED,
    STATE_TRUSTED,
)
from .coordinator import UniFiBlockerCoordinator
from .device_store import DeviceStore
from .unifi_api import UniFiApi

_LOGGER = logging.getLogger(__name__)

SERVICE_TRUST = "trust_device"
SERVICE_IGNORE = "ignore_device"
SERVICE_QUARANTINE = "quarantine_device"
SERVICE_BLOCK = "block_device"
SERVICE_UNBLOCK = "unblock_device"
SERVICE_RECONNECT = "reconnect_device"

MAC_SCHEMA = vol.Schema({vol.Required("mac"): cv.string})


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the integration (YAML not used, but required by HA)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Blocker from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    data = {**entry.data, **entry.options}

    api = UniFiApi(
        host=data[CONF_HOST],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        site=data.get(CONF_SITE, DEFAULT_SITE),
        verify_ssl=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    )

    try:
        await api.login()
    except Exception as err:
        _LOGGER.error("Failed to connect to UniFi controller: %s", err)
        await api.close()
        raise

    store = DeviceStore(hass)
    await store.async_load()

    coordinator = UniFiBlockerCoordinator(
        hass,
        api,
        store,
        update_interval=data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
    )
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api,
        "store": store,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # ── register sidebar panel & websocket API ──────────────────────────
    try:
        from .panel import async_register_panel
        await async_register_panel(hass)
    except Exception:
        _LOGGER.warning("Could not register sidebar panel", exc_info=True)

    try:
        from .websocket import async_register_websocket_commands
        async_register_websocket_commands(hass)
    except Exception:
        _LOGGER.warning("Could not register WebSocket commands", exc_info=True)

    # ── register services (only once) ────────────────────────────────

    if not hass.services.has_service(DOMAIN, SERVICE_TRUST):

        async def _get_entry_data() -> dict:
            """Return the first entry's runtime data dict."""
            for _eid, edata in hass.data.get(DOMAIN, {}).items():
                if isinstance(edata, dict) and "api" in edata:
                    return edata
            raise RuntimeError("No UniFi Blocker entry loaded")

        async def handle_trust(call: ServiceCall) -> None:
            d = await _get_entry_data()
            mac = call.data["mac"]
            await d["store"].set_state(mac, STATE_TRUSTED)
            await d["api"].unblock_client(mac)
            await d["coordinator"].async_request_refresh()

        async def handle_ignore(call: ServiceCall) -> None:
            d = await _get_entry_data()
            mac = call.data["mac"]
            await d["store"].set_state(mac, STATE_IGNORED)
            await d["coordinator"].async_request_refresh()

        async def handle_quarantine(call: ServiceCall) -> None:
            d = await _get_entry_data()
            mac = call.data["mac"]
            await d["store"].set_state(mac, STATE_QUARANTINED)
            await d["api"].block_client(mac)
            await d["coordinator"].async_request_refresh()

        async def handle_block(call: ServiceCall) -> None:
            d = await _get_entry_data()
            await d["api"].block_client(call.data["mac"])
            await d["coordinator"].async_request_refresh()

        async def handle_unblock(call: ServiceCall) -> None:
            d = await _get_entry_data()
            await d["api"].unblock_client(call.data["mac"])
            await d["coordinator"].async_request_refresh()

        async def handle_reconnect(call: ServiceCall) -> None:
            d = await _get_entry_data()
            await d["api"].reconnect_client(call.data["mac"])
            await d["coordinator"].async_request_refresh()

        hass.services.async_register(DOMAIN, SERVICE_TRUST, handle_trust, schema=MAC_SCHEMA)
        hass.services.async_register(DOMAIN, SERVICE_IGNORE, handle_ignore, schema=MAC_SCHEMA)
        hass.services.async_register(DOMAIN, SERVICE_QUARANTINE, handle_quarantine, schema=MAC_SCHEMA)
        hass.services.async_register(DOMAIN, SERVICE_BLOCK, handle_block, schema=MAC_SCHEMA)
        hass.services.async_register(DOMAIN, SERVICE_UNBLOCK, handle_unblock, schema=MAC_SCHEMA)
        hass.services.async_register(DOMAIN, SERVICE_RECONNECT, handle_reconnect, schema=MAC_SCHEMA)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id, {})
        api = entry_data.get("api")
        if api:
            await api.close()
    return unload_ok
