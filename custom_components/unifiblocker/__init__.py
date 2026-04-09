"""UniFi Blocker – network device review & quarantine for Home Assistant."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

DOMAIN = "unifiblocker"
PLATFORMS = ["sensor", "binary_sensor"]

try:
    from homeassistant.helpers.config_validation import config_entry_only_config_schema
    CONFIG_SCHEMA = config_entry_only_config_schema(DOMAIN)
except ImportError:
    import homeassistant.helpers.config_validation as cv
    CONFIG_SCHEMA = cv.removed(DOMAIN, raise_if_present=False)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    try:
        await _do_setup(hass, entry)
    except Exception:
        _LOGGER.exception("UniFi Blocker setup failed")
        raise

    return True


async def _do_setup(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """All real setup logic lives here — deferred imports only."""
    import voluptuous as vol
    from homeassistant.helpers import config_validation as cv

    from .const import (
        CONF_HOST, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_SITE,
        CONF_USERNAME, CONF_VERIFY_SSL, DEFAULT_SCAN_INTERVAL,
        DEFAULT_SITE, DEFAULT_VERIFY_SSL,
        STATE_IGNORED, STATE_QUARANTINED, STATE_TRUSTED,
    )
    from .coordinator import UniFiBlockerCoordinator
    from .device_store import DeviceStore
    from .unifi_api import UniFiApi

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

    # Port scanner (loaded before coordinator so it can auto-scan)
    try:
        from .port_scanner import PortScanner
        scanner = PortScanner()
    except Exception:
        _LOGGER.warning("Port scanner failed to load", exc_info=True)
        scanner = None

    coordinator = UniFiBlockerCoordinator(
        hass, api, store,
        update_interval=data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        scanner=scanner,
        onvif=onvif,
    )
    await coordinator.async_config_entry_first_refresh()

    # ONVIF probe engine
    try:
        from .onvif_probe import OnvifProbe
        onvif = OnvifProbe()
        # Run initial discovery in background (don't block startup).
        hass.async_create_task(onvif.discover_and_probe_all())
    except Exception:
        _LOGGER.warning("ONVIF probe failed to load", exc_info=True)
        onvif = None

    # Local network manager
    try:
        from .local_network import LocalNetworkManager
        local_net = LocalNetworkManager(hass)
        await local_net.async_load()
    except Exception:
        _LOGGER.warning("Local network manager failed to load", exc_info=True)
        local_net = None

    # Port scanner
    try:
        from .port_scanner import PortScanner
        scanner = PortScanner()
    except Exception:
        _LOGGER.warning("Port scanner failed to load", exc_info=True)
        scanner = None

    hass.data[DOMAIN][entry.entry_id] = {
        "api": api, "store": store, "coordinator": coordinator,
        "local_net": local_net, "scanner": scanner, "onvif": onvif,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Sidebar panel
    try:
        from .panel import async_register_panel
        await async_register_panel(hass)
    except Exception:
        _LOGGER.warning("Could not register sidebar panel", exc_info=True)

    # WebSocket API
    try:
        from .websocket import async_register_websocket_commands
        async_register_websocket_commands(hass)
    except Exception:
        _LOGGER.warning("Could not register WebSocket commands", exc_info=True)

    # Services
    MAC_SCHEMA = vol.Schema({vol.Required("mac"): cv.string})

    if not hass.services.has_service(DOMAIN, "trust_device"):
        async def _ed():
            for _, d in hass.data.get(DOMAIN, {}).items():
                if isinstance(d, dict) and "api" in d: return d
            raise RuntimeError("Not loaded")

        async def h_trust(c):
            d = await _ed(); await d["store"].set_state(c.data["mac"], STATE_TRUSTED); await d["api"].unblock_client(c.data["mac"]); await d["coordinator"].async_request_refresh()
        async def h_ignore(c):
            d = await _ed(); await d["store"].set_state(c.data["mac"], STATE_IGNORED); await d["coordinator"].async_request_refresh()
        async def h_quarantine(c):
            d = await _ed(); await d["store"].set_state(c.data["mac"], STATE_QUARANTINED); await d["api"].block_client(c.data["mac"]); await d["coordinator"].async_request_refresh()
        async def h_block(c):
            d = await _ed(); await d["api"].block_client(c.data["mac"]); await d["coordinator"].async_request_refresh()
        async def h_unblock(c):
            d = await _ed(); await d["api"].unblock_client(c.data["mac"]); await d["coordinator"].async_request_refresh()
        async def h_reconnect(c):
            d = await _ed(); await d["api"].reconnect_client(c.data["mac"]); await d["coordinator"].async_request_refresh()

        for n, h in [("trust_device", h_trust), ("ignore_device", h_ignore), ("quarantine_device", h_quarantine), ("block_device", h_block), ("unblock_device", h_unblock), ("reconnect_device", h_reconnect)]:
            hass.services.async_register(DOMAIN, n, h, schema=MAC_SCHEMA)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        entry_data = hass.data[DOMAIN].pop(entry.entry_id, {})
        api = entry_data.get("api")
        if api:
            await api.close()
    return unload_ok
