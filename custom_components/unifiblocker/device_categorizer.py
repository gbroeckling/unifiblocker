"""Device categorizer — classify every client on the network.

Determines what a device IS based on multiple signals:
  1. Vendor OUI (manufacturer)
  2. Hostname / mDNS name patterns
  3. UniFi-reported OUI string
  4. DPI traffic category weights
  5. Manual override (stored in device_store)

Categories
──────────
  camera        IP cameras, DVRs, NVRs
  computer      Desktops, laptops, workstations
  phone         Smartphones
  tablet        Tablets, iPads
  esphome       ESPHome / ESP32 / ESP8266 devices
  led           Smart lights, LED strips, WLED, Govee
  ha_device     Home Assistant instances, add-ons
  smart_speaker Smart speakers (Echo, Nest, HomePod)
  streaming     Streaming sticks (Roku, Chromecast, Fire TV, Apple TV)
  gaming        Consoles, gaming PCs
  printer       Printers, scanners
  networking    Routers, switches, APs, mesh nodes
  crypto        Crypto miners, ASIC devices
  iot           Generic IoT / smart home devices
  nas           NAS, storage appliances
  unknown       Could not determine
"""
from __future__ import annotations

from typing import Any

from .vendor_lookup import CAMERA_VENDORS, lookup_vendor_safe

# ── Category definitions ─────────────────────────────────────────────

CATEGORY_LABELS: dict[str, str] = {
    "camera": "Cameras",
    "computer": "Computers",
    "phone": "Phones",
    "tablet": "Tablets",
    "esphome": "ESPHome",
    "led": "Smart Lights",
    "ha_device": "HA Devices",
    "smart_speaker": "Speakers",
    "streaming": "Streaming",
    "gaming": "Gaming",
    "printer": "Printers",
    "networking": "Networking",
    "crypto": "Crypto",
    "iot": "IoT",
    "nas": "NAS / Storage",
    "unknown": "Unknown",
}

CATEGORY_ICONS: dict[str, str] = {
    "camera": "📹",
    "computer": "💻",
    "phone": "📱",
    "tablet": "📱",
    "esphome": "🔌",
    "led": "💡",
    "ha_device": "🏠",
    "smart_speaker": "🔊",
    "streaming": "📺",
    "gaming": "🎮",
    "printer": "🖨",
    "networking": "🌐",
    "crypto": "⛏",
    "iot": "🔧",
    "nas": "💾",
    "unknown": "❓",
}

# ── Vendor → category mapping ────────────────────────────────────────

_VENDOR_CATEGORY: dict[str, str] = {
    # Cameras (extend from CAMERA_VENDORS set)
    # Computers
    "Dell": "computer",
    "HP": "computer",
    "Lenovo": "computer",
    "ASUS": "computer",
    "Intel": "computer",
    "Microsoft": "computer",
    "Microsoft (Hyper-V)": "computer",
    # Phones
    "Apple": "phone",  # default; override by hostname
    "Samsung": "phone",
    "OnePlus": "phone",
    "Motorola": "phone",
    "Huawei": "phone",
    "Xiaomi": "phone",
    "Google": "phone",  # default; override by hostname
    # Smart speakers
    "Nest Labs": "smart_speaker",
    "Sonos": "smart_speaker",
    # Streaming
    "Roku": "streaming",
    "Nvidia": "streaming",
    # Gaming
    "Nintendo": "gaming",
    "Sony": "gaming",
    # Networking
    "Ubiquiti": "networking",
    "Netgear": "networking",
    "TP-Link": "networking",
    "Cisco": "networking",
    "Cisco Meraki": "networking",
    "Aruba": "networking",
    # ESPHome / Espressif
    "Espressif": "esphome",
    "Shelly / Espressif": "esphome",
    # Smart lights
    "Philips Hue": "led",
    # IoT
    "Tuya": "iot",
    "ecobee": "iot",
    "Belkin (Wemo)": "iot",
    "Belkin": "iot",
    "Yale / August": "iot",
    "Lutron": "iot",
    "Ring": "camera",
    "Wyze": "camera",
    # Printers
    # NAS
    "Synology": "nas",
    "QNAP": "nas",
    # VM
    "VMware": "computer",
    "QEMU/KVM virtual NIC": "computer",
    # Raspberry Pi
    "Raspberry Pi": "computer",
    # Vehicles
    "Tesla": "iot",
    # Amazon — depends on hostname
    "Amazon": "smart_speaker",
    # Broadcom / Realtek — too generic
    "Broadcom": "unknown",
    "Realtek": "unknown",
    # Camera-specific consumer brands
    "EZVIZ": "camera",
    "Imou": "camera",
    "Eufy": "camera",
    "YI Technology": "camera",
    "Wansview": "camera",
    "Hiseeu": "camera",
    "Zosi": "camera",
    "Annke": "camera",
    "Lorex": "camera",
    "Swann": "camera",
    "Foscam": "camera",
    "Amcrest": "camera",
    "TP-Link VIGI": "camera",
    "Axis": "camera",
    "Vivotek": "camera",
    "Hanwha/Samsung Techwin": "camera",
    "XMEye/Xiongmai": "camera",
    "Uniview": "camera",
    "Reolink": "camera",
    "Dahua": "camera",
    "Hikvision": "camera",
    "LG Electronics": "streaming",
}

# Also map all CAMERA_VENDORS
for _cv in CAMERA_VENDORS:
    if _cv not in _VENDOR_CATEGORY:
        _VENDOR_CATEGORY[_cv] = "camera"

# ── Hostname patterns → category ────────────────────────────────────
# Checked in order; first match wins.

_HOSTNAME_PATTERNS: list[tuple[list[str], str]] = [
    # ESPHome
    (["esphome", "esp32", "esp8266", "esp-", "esph-", "espresense"], "esphome"),
    # Home Assistant
    (["homeassistant", "home-assistant", "hassio", "hass.", "ha-", "supervisor"], "ha_device"),
    # WLED / Smart lights
    (["wled", "govee", "yeelight", "bulb", "light", "lamp", "led-", "lifx", "nanoleaf", "hue-"], "led"),
    # Cameras
    (["ipc", "ipcam", "camera", "cam-", "dvr", "nvr", "hikvision", "dahua",
      "dh-", "ds-", "reolink", "amcrest", "foscam", "xmeye", "ezviz", "imou"], "camera"),
    # Crypto miners
    (["miner", "antminer", "asic", "bitmain", "whatsminer", "avalon",
      "innosilicon", "goldshell", "helium", "bobcat", "rak", "sensecap",
      "nebra", "syncrobit", "crypto", "hashrate"], "crypto"),
    # Printers
    (["printer", "print", "epson", "canon-", "brother", "hp-printer",
      "laserjet", "officejet", "deskjet", "pixma", "mfc-"], "printer"),
    # Streaming
    (["roku", "chromecast", "firetv", "fire-tv", "appletv", "apple-tv",
      "shield", "nvidia-shield", "fire-stick", "firestick"], "streaming"),
    # Smart speakers
    (["echo", "alexa", "google-home", "googlehome", "nest-", "homepod",
      "nest-hub", "nest-mini", "echo-dot", "echo-show"], "smart_speaker"),
    # Gaming
    (["playstation", "ps4", "ps5", "xbox", "nintendo", "switch-",
      "steam-deck", "steamdeck", "game-pc", "gaming"], "gaming"),
    # Phones / tablets
    (["iphone", "ipad", "galaxy", "pixel", "oneplus", "android-"], "phone"),
    (["ipad", "galaxy-tab", "tablet", "kindle", "fire-hd", "surface-go"], "tablet"),
    # Computers
    (["desktop", "laptop", "macbook", "imac", "mac-pro", "mac-mini",
      "thinkpad", "dell-", "hp-", "surface", "pc-", "workstation",
      "windows", "win-", "linux-"], "computer"),
    # NAS
    (["nas", "synology", "diskstation", "qnap", "truenas", "freenas",
      "unraid"], "nas"),
    # Networking
    (["router", "switch", "gateway", "ap-", "access-point", "mesh",
      "ubnt", "unifi", "uap", "usw", "uxg", "ucg", "udm", "usg"], "networking"),
    # IoT catch-all
    (["smart-", "iot-", "sensor-", "thermostat", "doorbell", "lock-",
      "plug-", "outlet-", "switch-", "relay-", "zigbee", "zwave"], "iot"),
]

# ── Apple device refinement by hostname ──────────────────────────────
_APPLE_HOSTNAME_HINTS: dict[str, str] = {
    "iphone": "phone",
    "ipad": "tablet",
    "macbook": "computer",
    "imac": "computer",
    "mac-pro": "computer",
    "mac-mini": "computer",
    "appletv": "streaming",
    "apple-tv": "streaming",
    "homepod": "smart_speaker",
}

# ── Amazon device refinement by hostname ─────────────────────────────
_AMAZON_HOSTNAME_HINTS: dict[str, str] = {
    "echo": "smart_speaker",
    "alexa": "smart_speaker",
    "fire-tv": "streaming",
    "firetv": "streaming",
    "firestick": "streaming",
    "fire-stick": "streaming",
    "kindle": "tablet",
    "fire-hd": "tablet",
    "ring": "camera",
    "blink": "camera",
}

# ── Google device refinement ─────────────────────────────────────────
_GOOGLE_HOSTNAME_HINTS: dict[str, str] = {
    "chromecast": "streaming",
    "google-home": "smart_speaker",
    "googlehome": "smart_speaker",
    "nest-hub": "smart_speaker",
    "nest-mini": "smart_speaker",
    "nest-cam": "camera",
    "nest-doorbell": "camera",
    "pixel": "phone",
}


def categorize_device(
    mac: str,
    hostname: str = "",
    vendor: str = "",
    oui: str = "",
    dpi_cats: list[dict] | None = None,
    manual_category: str | None = None,
    scan_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify a device using ALL available signals.

    Priority order:
      1. Manual override (user explicitly set it)
      2. Port scan results (strongest automated signal — proves what it IS)
      3. Known camera vendor OUI (high confidence)
      4. Camera chip vendor + any camera signal (medium-high confidence)
      5. Hostname patterns
      6. General vendor OUI mapping
      7. DPI traffic patterns
      8. Unknown
    """
    # 1. Manual override always wins.
    if manual_category and manual_category in CATEGORY_LABELS:
        return _result(manual_category, "high", "manual")

    if not vendor:
        vendor = oui or lookup_vendor_safe(mac)

    hn = (hostname or "").lower().strip()

    # 2. PORT SCAN — the strongest signal. If we scanned the device
    #    and found camera ports, that PROVES what it is.
    if scan_result and scan_result.get("status") == "complete":
        scan_cat = scan_result.get("guess_category", "unknown")
        scan_conf = scan_result.get("guess_confidence", "low")
        open_ports = scan_result.get("open_ports", [])

        # If the scan identified it as a camera with any confidence, trust it.
        if scan_cat == "camera":
            return _result("camera", "high", "port_scan")

        # RTSP port 554 open = camera (almost always)
        if 554 in open_ports:
            return _result("camera", "high", "port_scan")

        # ONVIF ports = camera
        if any(p in open_ports for p in [3702, 8899, 2020, 6000]):
            return _result("camera", "high", "port_scan")

        # Any Hikvision/Dahua/XMEye specific port = camera
        if any(p in open_ports for p in [8000, 9527, 8200, 37777, 37778, 34567, 34568, 9530]):
            return _result("camera", "high", "port_scan")

        # Camera cloud ports = camera
        if any(p in open_ports for p in [6789, 32100, 19000, 8800, 15000, 20000]):
            return _result("camera", "high", "port_scan")

        # Scan identified a non-camera category with medium+ confidence
        if scan_cat != "unknown" and scan_conf in ("high", "medium"):
            return _result(scan_cat, scan_conf, "port_scan")

    # 3. Known camera vendor OUI — high confidence
    if vendor in CAMERA_VENDORS:
        return _result("camera", "high", "vendor")

    # 4. Camera chip vendor (HiSilicon, Ingenic, etc.)
    #    These PROBABLY make cameras but could be other embedded devices.
    #    Promote to camera if ANY other signal suggests camera.
    from .vendor_lookup import CAMERA_CHIP_VENDORS
    if vendor in CAMERA_CHIP_VENDORS:
        # Any camera hostname hint?
        cam_hints = ["ipc", "cam", "dvr", "nvr", "ds-", "dh-", "hik", "dahua"]
        if hn and any(h in hn for h in cam_hints):
            return _result("camera", "high", "vendor+hostname")
        # No hostname at all? Chip vendor + no hostname = very likely camera.
        if not hn:
            return _result("camera", "medium", "vendor+no_hostname")
        # Has a hostname but it doesn't look like a camera — still flag as probable.
        return _result("camera", "low", "chip_vendor")

    # 5. Vendor-specific hostname refinement (Apple, Amazon, Google)
    if vendor in ("Apple",):
        for hint, cat in _APPLE_HOSTNAME_HINTS.items():
            if hint in hn:
                return _result(cat, "high", "hostname")

    if vendor in ("Amazon",):
        for hint, cat in _AMAZON_HOSTNAME_HINTS.items():
            if hint in hn:
                return _result(cat, "high", "hostname")

    if vendor in ("Google", "Nest Labs"):
        for hint, cat in _GOOGLE_HOSTNAME_HINTS.items():
            if hint in hn:
                return _result(cat, "high", "hostname")

    # 6. Hostname pattern matching (any vendor)
    if hn:
        for patterns, cat in _HOSTNAME_PATTERNS:
            for pat in patterns:
                if pat in hn:
                    return _result(cat, "high" if len(pat) > 4 else "medium", "hostname")

    # 7. General vendor OUI mapping
    if vendor in _VENDOR_CATEGORY:
        cat = _VENDOR_CATEGORY[vendor]
        return _result(cat, "medium", "vendor")

    # 8. DPI-based inference
    if dpi_cats:
        cat = _infer_from_dpi(dpi_cats)
        if cat:
            return _result(cat, "low", "dpi")

    # 9. Unknown vendor + no hostname = suspicious, flag for scan
    if vendor == "Unknown" and not hn:
        return _result("unknown", "low", "none")

    return _result("unknown", "low", "none")


def _result(category: str, confidence: str, source: str) -> dict[str, Any]:
    return {
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, "Unknown"),
        "category_icon": CATEGORY_ICONS.get(category, "❓"),
        "confidence": confidence,
        "source": source,
    }


def _infer_from_dpi(dpi_cats: list[dict]) -> str | None:
    """Try to infer category from DPI traffic patterns."""
    if not dpi_cats:
        return None

    # Build a traffic volume map by DPI category ID.
    volumes: dict[int, float] = {}
    for cat in dpi_cats:
        cid = cat.get("cat") or cat.get("cat_id")
        if cid is not None:
            rx = cat.get("rx_bytes", 0) or cat.get("rx_mb", 0) * 1_000_000
            tx = cat.get("tx_bytes", 0) or cat.get("tx_mb", 0) * 1_000_000
            volumes[cid] = rx + tx

    if not volumes:
        return None

    top_cat = max(volumes, key=volumes.get)
    top_vol = volumes[top_cat]

    # If dominant traffic is streaming and volume is high → streaming/camera
    if top_cat == 3 and top_vol > 100_000_000:  # 100 MB streaming
        return "streaming"
    # P2P heavy → could be crypto
    if top_cat == 1 and top_vol > 500_000_000:  # 500 MB P2P
        return "crypto"
    # Gaming
    if top_cat == 7 and top_vol > 10_000_000:
        return "gaming"

    return None


def categorize_all_clients(
    clients: list[dict[str, Any]],
    dpi_data: dict[str, dict[str, Any]] | None = None,
    manual_overrides: dict[str, str] | None = None,
    scan_data: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    """Categorize every client. Returns mac → category result."""
    results: dict[str, dict[str, Any]] = {}
    for client in clients:
        mac = client.get("mac", "").lower()
        if not mac:
            continue
        hostname = client.get("hostname") or client.get("name") or ""
        vendor = client.get("oui") or lookup_vendor_safe(mac)
        dpi_entry = (dpi_data or {}).get(mac, {})
        dpi_cats = dpi_entry.get("top_categories") or dpi_entry.get("by_cat")
        manual = (manual_overrides or {}).get(mac)
        scan = (scan_data or {}).get(mac)

        results[mac] = categorize_device(
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            dpi_cats=dpi_cats,
            manual_category=manual,
            scan_result=scan,
        )
    return results


def get_category_counts(
    categorized: dict[str, dict[str, Any]]
) -> dict[str, int]:
    """Return {category: count} for all categories with devices."""
    counts: dict[str, int] = {}
    for info in categorized.values():
        cat = info.get("category", "unknown")
        counts[cat] = counts.get(cat, 0) + 1
    return counts
