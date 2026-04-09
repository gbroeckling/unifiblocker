"""Port identification and traffic classification.

Maps well-known ports to human-readable descriptions and classifies
what a device is likely doing based on its open/active ports.

The UCG Max doesn't directly expose per-client port lists, but it does
expose DPI categories and application data.  This module also maps the
UniFi DPI category IDs to readable names and provides a port reference
used when ports are available from other sources (e.g. firewall logs
or manual scans).
"""
from __future__ import annotations

from typing import Any

# ── Well-known ports → description ───────────────────────────────────

PORT_MAP: dict[int, dict[str, str]] = {
    # Web / HTTP
    80:    {"name": "HTTP", "meaning": "Web traffic (unencrypted)", "category": "web"},
    443:   {"name": "HTTPS", "meaning": "Web traffic (encrypted TLS)", "category": "web"},
    8080:  {"name": "HTTP-alt", "meaning": "Web admin / proxy / camera web UI", "category": "web"},
    8443:  {"name": "HTTPS-alt", "meaning": "Secure web admin (UniFi, cameras)", "category": "web"},
    # Streaming / media
    554:   {"name": "RTSP", "meaning": "Real-Time Streaming Protocol — IP camera live stream", "category": "camera"},
    1935:  {"name": "RTMP", "meaning": "Real-Time Messaging Protocol — live video streaming", "category": "camera"},
    8554:  {"name": "RTSP-alt", "meaning": "Alternate RTSP — some cameras use this", "category": "camera"},
    8555:  {"name": "RTSP-alt", "meaning": "Alternate RTSP stream port", "category": "camera"},
    6000:  {"name": "X11/ONVIF", "meaning": "ONVIF camera discovery or X11 display", "category": "camera"},
    # Camera-specific
    34567: {"name": "XMEye", "meaning": "XMEye/Xiongmai DVR protocol — Chinese DVR phoning home", "category": "camera_phome"},
    34568: {"name": "XMEye-media", "meaning": "XMEye media stream — DVR video data", "category": "camera_phome"},
    9527:  {"name": "Hikvision-SDK", "meaning": "Hikvision SDK port — camera management", "category": "camera"},
    9530:  {"name": "Dahua-debug", "meaning": "Dahua debug/backdoor port", "category": "camera_phome"},
    37777: {"name": "Dahua-TCP", "meaning": "Dahua TCP service — DVR/NVR connection", "category": "camera"},
    37778: {"name": "Dahua-UDP", "meaning": "Dahua UDP service — DVR/NVR media", "category": "camera"},
    8000:  {"name": "Hikvision-mgmt", "meaning": "Hikvision management/SDK port", "category": "camera"},
    8200:  {"name": "Hikvision-ISAPI", "meaning": "Hikvision ISAPI web services", "category": "camera"},
    # DNS
    53:    {"name": "DNS", "meaning": "Domain name resolution", "category": "network"},
    5353:  {"name": "mDNS", "meaning": "Multicast DNS / Bonjour discovery", "category": "network"},
    # DHCP
    67:    {"name": "DHCP-server", "meaning": "DHCP server (rogue DHCP?)", "category": "network"},
    68:    {"name": "DHCP-client", "meaning": "DHCP client — getting IP address", "category": "network"},
    # NTP
    123:   {"name": "NTP", "meaning": "Network time sync", "category": "network"},
    # UPnP / SSDP
    1900:  {"name": "SSDP/UPnP", "meaning": "UPnP discovery — can open firewall holes", "category": "risky"},
    5000:  {"name": "UPnP-media", "meaning": "UPnP media server / Synology DSM", "category": "network"},
    # SSH / Telnet
    22:    {"name": "SSH", "meaning": "Secure shell — remote management", "category": "admin"},
    23:    {"name": "Telnet", "meaning": "Telnet — insecure remote access (backdoor risk)", "category": "risky"},
    2323:  {"name": "Telnet-alt", "meaning": "Alternate telnet — often used by IoT malware", "category": "risky"},
    # Cloud phone-home
    6789:  {"name": "P2P-cloud", "meaning": "P2P cloud relay — camera phoning home to China", "category": "camera_phome"},
    32100: {"name": "Reolink-P2P", "meaning": "Reolink P2P cloud connection", "category": "camera_phome"},
    8800:  {"name": "Cloud-relay", "meaning": "Cloud relay service — device calling home", "category": "camera_phome"},
    19000: {"name": "EZVIZ-P2P", "meaning": "EZVIZ/Hikvision P2P cloud relay", "category": "camera_phome"},
    # MQTT / IoT
    1883:  {"name": "MQTT", "meaning": "MQTT messaging — IoT device communication", "category": "iot"},
    8883:  {"name": "MQTT-TLS", "meaning": "MQTT over TLS — encrypted IoT messaging", "category": "iot"},
    # VPN
    1194:  {"name": "OpenVPN", "meaning": "OpenVPN tunnel", "category": "vpn"},
    51820: {"name": "WireGuard", "meaning": "WireGuard VPN tunnel", "category": "vpn"},
    # Mail
    25:    {"name": "SMTP", "meaning": "Email sending — could be spam/exfil", "category": "risky"},
    587:   {"name": "SMTP-submit", "meaning": "Email submission — sending mail", "category": "risky"},
    # FTP
    21:    {"name": "FTP", "meaning": "File transfer (insecure) — data exfiltration risk", "category": "risky"},
    # SMB / file sharing
    445:   {"name": "SMB", "meaning": "Windows file sharing — lateral movement risk", "category": "risky"},
    139:   {"name": "NetBIOS", "meaning": "NetBIOS session — legacy file sharing", "category": "risky"},
}

# Categories above that indicate concerning behavior.
RISKY_CATEGORIES = {"camera_phome", "risky"}

# ── UniFi DPI category IDs → readable names ─────────────────────────

DPI_CATEGORIES: dict[int, str] = {
    0: "Instant Messaging",
    1: "P2P",
    2: "File Transfer",
    3: "Streaming Media",
    4: "Mail & Calendar",
    5: "VoIP & Video Calls",
    6: "Database",
    7: "Gaming",
    8: "Network Management",
    9: "Remote Access",
    10: "Unclassified (Unknown)",
    11: "Business Apps",
    12: "Network Protocols",
    13: "IoT & Automation",
    14: "Security & VPN",
    15: "Web",
    16: "Social & Media",
    17: "Advertising & Analytics",
    18: "Cloud Storage",
    19: "OS Updates",
    20: "DNS",
}


def identify_port(port: int) -> dict[str, str]:
    """Return info about a port, or a generic 'unknown' entry."""
    return PORT_MAP.get(port, {
        "name": f"Port {port}",
        "meaning": "Unknown service",
        "category": "unknown",
    })


def classify_dpi_category(cat_id: int) -> str:
    """Return a human name for a UniFi DPI category ID."""
    return DPI_CATEGORIES.get(cat_id, f"Category {cat_id}")


def analyze_dpi_entry(dpi: dict[str, Any]) -> dict[str, Any]:
    """Analyze a single client's DPI data.

    Returns a summary with top categories, total bytes, and any
    concerning patterns (e.g. high P2P, cloud phone-home traffic).
    """
    mac = dpi.get("mac", "")
    by_cat = dpi.get("by_cat", [])
    by_app = dpi.get("by_app", [])

    categories: list[dict[str, Any]] = []
    total_rx = 0
    total_tx = 0

    for cat in by_cat:
        cat_id = cat.get("cat")
        rx = cat.get("rx_bytes", 0)
        tx = cat.get("tx_bytes", 0)
        total_rx += rx
        total_tx += tx
        categories.append({
            "category": classify_dpi_category(cat_id),
            "cat_id": cat_id,
            "rx_mb": round(rx / 1_000_000, 2),
            "tx_mb": round(tx / 1_000_000, 2),
        })

    # Sort by total traffic descending.
    categories.sort(key=lambda c: c["rx_mb"] + c["tx_mb"], reverse=True)

    # Flag concerning patterns.
    flags: list[str] = []
    for cat in categories:
        cid = cat["cat_id"]
        total = cat["rx_mb"] + cat["tx_mb"]
        if cid == 1 and total > 10:  # P2P > 10 MB
            flags.append(f"High P2P traffic ({total:.1f} MB) — possible cloud relay")
        if cid == 3 and total > 100:  # Streaming > 100 MB
            flags.append(f"High streaming traffic ({total:.1f} MB) — video upload?")
        if cid == 9 and total > 5:    # Remote Access > 5 MB
            flags.append(f"Remote access traffic ({total:.1f} MB) — phone home?")

    return {
        "mac": mac,
        "total_rx_mb": round(total_rx / 1_000_000, 2),
        "total_tx_mb": round(total_tx / 1_000_000, 2),
        "top_categories": categories[:5],
        "flags": flags,
    }
