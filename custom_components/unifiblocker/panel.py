"""Register the UniFi Blocker sidebar panel."""
from __future__ import annotations

import logging
import os

from homeassistant.components import panel_custom
from homeassistant.components.http import StaticPathConfig
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

PANEL_ICON = "mdi:shield-lock"
PANEL_TITLE = "UniFi Blocker"

# Path inside the integration package where the JS lives.
_WWW_DIR = os.path.join(os.path.dirname(__file__), "www", "unifiblocker")
_URL_BASE = "/unifiblocker_panel"


async def async_register_panel(hass: HomeAssistant) -> None:
    """Register a static path for the JS and then the sidebar panel."""

    # Serve the www/ directory at /unifiblocker_panel/
    await hass.http.async_register_static_paths(
        [StaticPathConfig(_URL_BASE, _WWW_DIR, cache_headers=False)]
    )

    await panel_custom.async_register_panel(
        hass,
        webcomponent_name="unifiblocker-panel",
        frontend_url_path="unifiblocker",
        sidebar_title=PANEL_TITLE,
        sidebar_icon=PANEL_ICON,
        module_url=f"{_URL_BASE}/panel.js",
        embed_iframe=False,
        require_admin=False,
        config={},
    )
    _LOGGER.info("UniFi Blocker sidebar panel registered")
