"""Register the UniFi Blocker sidebar panel."""
from __future__ import annotations

import logging

from homeassistant.components import panel_custom
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

PANEL_URL = "/api/panel_custom/unifiblocker"
PANEL_ICON = "mdi:shield-lock"
PANEL_TITLE = "UniFi Blocker"


async def async_register_panel(hass: HomeAssistant) -> None:
    """Register the custom sidebar panel."""
    await panel_custom.async_register_panel(
        hass,
        webcomponent_name="unifiblocker-panel",
        frontend_url_path="unifiblocker",
        sidebar_title=PANEL_TITLE,
        sidebar_icon=PANEL_ICON,
        module_url="/local/unifiblocker/panel.js",
        embed_iframe=False,
        require_admin=False,
        config={},
    )
    _LOGGER.info("UniFi Blocker sidebar panel registered")
