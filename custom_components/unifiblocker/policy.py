"""What happens when something new shows up on the network.

new_camera_policy (options):
    block_internet  default. Add the "UB: <mac> no internet" traffic rule so
                    the camera can't reach the internet. Its IP doesn't
                    change, so local viewing and recording keep working.
                    Trusting the camera removes the rule again.
    notify          a notification only
    off             nothing (the unifiblocker_new_camera event still fires)

new_device_policy (options): notify (default) / off, for everything else.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

CAMERA_POLICIES = ("block_internet", "notify", "off")
DEVICE_POLICIES = ("notify", "off")
DEFAULT_CAMERA_POLICY = "block_internet"
DEFAULT_DEVICE_POLICY = "notify"


def _notify(hass: HomeAssistant, title: str, message: str, nid: str) -> None:
    from homeassistant.components import persistent_notification
    persistent_notification.async_create(hass, message, title=title, notification_id=nid)


async def on_new_camera(hass: HomeAssistant, policy: str, api: Any, local_net: Any,
                        store: Any, cam: dict[str, Any]) -> None:
    """Apply the new-camera policy to one camera seen for the first time."""
    if policy == "off":
        return
    mac = cam["mac"].lower()
    name = cam.get("name") or mac
    what = f"**{name}** ({cam.get('vendor') or 'unknown maker'}, {cam.get('ip') or 'no IP'})"
    if policy == "block_internet" and local_net is not None:
        try:
            result = await local_net.block_device_internet(api, mac)
        except Exception as err:  # never let this break the poll
            result = {"ok": False, "error": str(err)}
        if result.get("ok"):
            store.mark_auto_blocked(mac, result.get("rule_id", ""))
            _notify(hass, "New camera cut off from the internet",
                    f"UniFi Blocker found a new camera, {what}, and blocked it from reaching the internet. "
                    "It still works on your local network.\n\nIf it's yours and needs its cloud app (some cameras "
                    "need the internet once to finish setting up), **Trust** it in the UniFi Blocker panel to "
                    "remove the block.", f"{DOMAIN}_cam_{mac}")
            return
        _LOGGER.warning("Couldn't block new camera %s: %s", mac, result.get("error"))
    _notify(hass, "New camera on your network",
            f"UniFi Blocker found a new camera, {what}. Open the UniFi Blocker panel to put it on local-only "
            "or trust it.", f"{DOMAIN}_cam_{mac}")


def on_new_devices(hass: HomeAssistant, policy: str, devices: list[dict[str, Any]]) -> None:
    """One notification listing devices seen for the first time."""
    if policy == "off" or not devices:
        return
    lines = "\n".join(f"- {d.get('name') or d.get('hostname') or d['mac']} "
                      f"({d.get('vendor') or d.get('oui') or 'unknown maker'}, {d.get('ip') or 'no IP'})"
                      for d in devices[:15])
    more = f"\n- and {len(devices) - 15} more" if len(devices) > 15 else ""
    _notify(hass, f"{len(devices)} new device{'s' if len(devices) != 1 else ''} on your network",
            f"{lines}{more}\n\nReview them in the UniFi Blocker panel.", f"{DOMAIN}_new_devices")


async def trust(entry: dict[str, Any], mac: str) -> None:
    """Trust a device: mark it, unblock it on the controller, and remove an
    internet block the new-camera policy put on it."""
    from .const import STATE_TRUSTED
    await entry["store"].set_state(mac, STATE_TRUSTED)
    await entry["api"].unblock_client(mac)
    if entry["store"].auto_blocked(mac) and entry.get("local_net"):
        try:
            await entry["local_net"].unblock_device_internet(entry["api"], mac)
        except Exception:
            _LOGGER.warning("Couldn't remove the internet block for %s", mac, exc_info=True)
        await entry["store"].clear_auto_blocked(mac)
    await entry["coordinator"].async_request_refresh()
