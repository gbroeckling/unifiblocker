"""Register the UniFi Blocker sidebar panel."""
from __future__ import annotations

import logging
import os
import time

from homeassistant.components import frontend, panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

PANEL_ICON = "mdi:shield-lock"
PANEL_TITLE = "UniFi Blocker"

_WWW_DIR = os.path.join(os.path.dirname(__file__), "www", "unifiblocker")
_URL_BASE = "/unifiblocker_panel"
_PANEL_PATH = "unifiblocker"
_STATIC_REGISTERED = "unifiblocker_static_registered"

# Cache-bust: append timestamp so browsers always load the latest JS.
_CACHE_BUST = str(int(time.time()))


async def async_register_panel(hass: HomeAssistant) -> None:
    """Register a static path for the JS and then the sidebar panel."""

    # Static routes can't be removed from aiohttp, so only register once per
    # HA run. Otherwise a reload of the integration fails here and the panel
    # never comes back.
    if not hass.data.get(_STATIC_REGISTERED):
        await hass.http.async_register_static_paths(
            [StaticPathConfig(_URL_BASE, _WWW_DIR, cache_headers=False)]
        )
        hass.data[_STATIC_REGISTERED] = True

    await panel_custom.async_register_panel(
        hass,
        webcomponent_name="unifiblocker-panel",
        frontend_url_path=_PANEL_PATH,
        sidebar_title=PANEL_TITLE,
        sidebar_icon=PANEL_ICON,
        module_url=f"{_URL_BASE}/panel.js?v={_CACHE_BUST}",
        embed_iframe=False,
        require_admin=True,
        config={},
    )
    _LOGGER.info("UniFi Blocker sidebar panel registered (cache bust: %s)", _CACHE_BUST)


def async_unregister_panel(hass: HomeAssistant) -> None:
    """Remove the sidebar panel (called on unload)."""
    frontend.async_remove_panel(hass, _PANEL_PATH)
