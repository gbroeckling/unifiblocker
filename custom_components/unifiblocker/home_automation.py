"""Home automation devices: how much do they depend on someone else's cloud?

Three tiers:
  local         you run the firmware or it has no cloud: ESPHome, WLED,
                Tasmota, Zigbee coordinators, Home Assistant itself.
  cloud_local   ships talking to a cloud but has a local way in, so it can
                go on local-only once Home Assistant uses the local route
                (Tuya via LocalTuya, Shelly, Kasa, Govee LAN, Xiaomi miio...).
  cloud         only works through the maker's cloud; cutting it off breaks
                it (Wyze, Ring, Echo/Google, most vacuums).

Cutting a cloud-tied device off without switching to the local route
first breaks it, so the advice differs per tier.
"""
from __future__ import annotations

import re
from typing import Any

HA_CATEGORIES = frozenset({"esphome", "led", "iot", "smart_speaker", "ha_device"})

# (pattern over "hostname vendor onvif-manufacturer cloud", brand, tier, local option)
_BRANDS: list[tuple[str, str, str, str]] = [
    (r"\besphome\b|\besp(?:32|8266)?-[0-9a-f]{6}\b", "ESPHome", "local", ""),
    (r"\bwled\b", "WLED", "local", ""),
    (r"\btasmota\b", "Tasmota", "local", ""),
    (r"\bslzb-|\bzigstar\b|\bsonoff[-_ ]?zb|\bconbee\b|\bzigbee\b", "Zigbee coordinator", "local", ""),
    (r"\bhomeassistant\b|\bhassio\b|\bhome-assistant\b", "Home Assistant", "local", ""),
    (r"\bshelly", "Shelly", "cloud_local", "Shelly works fully locally: use the Shelly integration and turn off Shelly Cloud in the device's settings."),
    (r"\btuya\b|\bsmart ?life\b|\bsmartlife\b", "Tuya / Smart Life", "cloud_local",
     "Use LocalTuya or Tuya Local in Home Assistant with the device's local key, then it can go on local-only."),
    (r"\b(?:hs1\d\d|hs2\d\d|kp\d{3}|kl\d{3}|ep\d\d)\b|\bkasa\b|tp-?link kasa", "TP-Link Kasa", "cloud_local",
     "Kasa devices have a local API; the TP-Link Kasa integration uses it."),
    (r"\btapo[_-]|\bp1\d\d\b|\bl5\d\d\b|tp-?link kasa/tapo", "TP-Link Tapo", "cloud_local",
     "Newer Tapo firmware needs a one-time cloud login, then the TP-Link integration can control it locally."),
    (r"\bihoment_|\bgovee\b", "Govee", "cloud_local", "Turn on LAN Control in the Govee app, then use the Govee LAN integration."),
    (r"\byeelink-|\bzhimi-|\bchuangmi-|\blumi-|\bxiaomi\b|\bmiio\b", "Xiaomi", "cloud_local",
     "Get the device token once, then the Xiaomi Miio integration works locally."),
    (r"\broborock\b|\brockrobo\b", "Roborock", "cloud_local", "Valetudo replaces the cloud firmware on many Roborock models."),
    (r"\bmeross\b", "Meross", "cloud_local", "Meross LAN (HACS) controls them locally."),
    (r"\bbroadlink\b", "Broadlink", "cloud_local", "The Broadlink integration is local."),
    (r"\bsonoff\b|\bitead\b|\bewelink\b", "Sonoff (eWeLink)", "cloud_local",
     "Use the device's LAN mode with the Sonoff LAN integration, or flash Tasmota/ESPHome."),
    (r"\bphilips[- ]hue\b|\bhue[-_ ]?bridge\b|\bsignify\b", "Philips Hue", "cloud_local", "The Hue bridge has a local API; the Hue integration uses it."),
    (r"\bikea\b|\bdirigera\b|\btradfri\b", "IKEA", "cloud_local", "The IKEA hub is controlled locally."),
    (r"\becobee\b", "ecobee", "cloud_local", "The HomeKit Device integration controls ecobee thermostats locally."),
    (r"\bcontrol4\b|\bwi2wi\b", "Control4", "cloud_local",
     "Control4 runs locally; its cloud (4Sight) is only for remote access and updates."),
    (r"\bvera\b|\bsercomm\b", "Vera", "local", ""),
    (r"\bcoulomb\b|\bchargepoint\b", "ChargePoint", "cloud", ""),
    (r"\bwyze\b", "Wyze", "cloud", ""),
    (r"\bring\b|ring \(amazon\)", "Ring", "cloud", ""),
    (r"\becho\b|\balexa\b", "Amazon Echo", "cloud", ""),
    (r"\bgoogle-home\b|\bgooglehome\b|\bnest\b|\bchromecast\b", "Google / Nest", "cloud", ""),
    (r"\becovacs\b|\bdreame\b|\birobot\b|\broomba\b", "Robot vacuum", "cloud", ""),
    (r"\beufy\b", "Eufy", "cloud", ""),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), b, t, h) for p, b, t, h in _BRANDS]

TIER_LABELS = {"local": "Local", "cloud_local": "Cloud, local option", "cloud": "Cloud only"}


def classify(device: dict[str, Any]) -> dict[str, Any] | None:
    """Brand and tier for an enriched client, or None if it isn't home
    automation. Cameras are left to the camera checks."""
    if device.get("is_camera"):
        return None
    clouds = " ".join(((device.get("phone_home") or {}).get("clouds") or {}).keys())
    hay = " ".join(str(x) for x in (device.get("hostname"), device.get("name"), device.get("vendor"),
                                    device.get("onvif_manufacturer"), clouds) if x)
    for rx, brand, tier, hint in _COMPILED:
        if rx.search(hay):
            return {"brand": brand, "tier": tier, "tier_label": TIER_LABELS[tier], "local_option": hint}
    if device.get("category") == "smart_speaker" and "amazon" in str(device.get("vendor", "")).lower():
        return {"brand": "Amazon Echo", "tier": "cloud", "tier_label": TIER_LABELS["cloud"], "local_option": ""}
    if device.get("category") == "esphome":
        return {"brand": "ESPHome", "tier": "local", "tier_label": TIER_LABELS["local"], "local_option": ""}
    if device.get("category") in HA_CATEGORIES:
        return {"brand": "", "tier": "unknown", "tier_label": "Not sure", "local_option": ""}
    return None
