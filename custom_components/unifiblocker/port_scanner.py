"""Async port scanner and device fingerprinter.

Scans a targeted list of ports on each device and uses the combination
of open ports, along with vendor and hostname data, to make an educated
guess about what the device is, what it's doing, and what security risk
it poses.

This is NOT a full Nmap-style scanner — it's a focused, fast TCP connect
scan of ~90 ports that matter for device identification and security.
Designed to run on-demand (not every poll cycle) and cache results.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

_LOGGER = logging.getLogger(__name__)

# ── Scan configuration ───────────────────────────────────────────────

CONNECT_TIMEOUT = 1.5   # seconds per port
MAX_CONCURRENT = 30     # parallel connections per device
SCAN_COOLDOWN = 300     # don't re-scan same device within 5 minutes

# ── Port list (targeted, not exhaustive) ─────────────────────────────
# Grouped by purpose so results are meaningful.

SCAN_PORTS: dict[int, dict[str, str]] = {
    # ═══ CAMERA / SURVEILLANCE (comprehensive) ═══════════════════════
    #
    # RTSP — the universal IP camera streaming protocol
    554:   {"name": "RTSP", "group": "camera"},
    8554:  {"name": "RTSP-alt (go2rtc, Frigate)", "group": "camera"},
    8555:  {"name": "RTSP-alt2 / WebRTC", "group": "camera"},
    1554:  {"name": "RTSP-alt3", "group": "camera"},
    10554: {"name": "RTSP-alt (some Dahua)", "group": "camera"},
    #
    # RTMP — live video push
    1935:  {"name": "RTMP live push", "group": "camera"},
    #
    # ONVIF — open standard camera discovery and control
    80:    {"name": "HTTP (ONVIF default)", "group": "web"},
    8080:  {"name": "HTTP-alt (ONVIF common alt)", "group": "web"},
    8899:  {"name": "ONVIF HTTP (some cameras)", "group": "onvif"},
    2020:  {"name": "ONVIF (Axis default)", "group": "onvif"},
    3702:  {"name": "WS-Discovery (ONVIF probe)", "group": "onvif"},
    6000:  {"name": "ONVIF media service", "group": "onvif"},
    8081:  {"name": "ONVIF alt / camera snapshot", "group": "onvif"},
    8082:  {"name": "ONVIF alt / secondary stream", "group": "onvif"},
    #
    # Hikvision-specific ports
    8000:  {"name": "Hikvision SDK (iVMS-4200)", "group": "camera_hik"},
    8200:  {"name": "Hikvision ISAPI", "group": "camera_hik"},
    9527:  {"name": "Hikvision SDK debug", "group": "camera_hik"},
    8009:  {"name": "Hikvision alarm push", "group": "camera_hik"},
    7681:  {"name": "Hikvision websocket stream", "group": "camera_hik"},
    443:   {"name": "HTTPS (Hik ISAPI/web)", "group": "web"},
    #
    # Dahua-specific ports
    37777: {"name": "Dahua TCP service", "group": "camera_dahua"},
    37778: {"name": "Dahua UDP/media", "group": "camera_dahua"},
    37780: {"name": "Dahua HTTP API", "group": "camera_dahua"},
    37781: {"name": "Dahua HTTPS API", "group": "camera_dahua"},
    5000:  {"name": "Dahua/Synology web (ambiguous)", "group": "camera_dahua"},
    9530:  {"name": "Dahua debug BACKDOOR", "group": "camera_dahua_backdoor"},
    38888: {"name": "Dahua NVR config backup", "group": "camera_dahua"},
    #
    # XMEye / Xiongmai DVR ports
    34567: {"name": "XMEye control protocol", "group": "camera_xmeye"},
    34568: {"name": "XMEye media stream", "group": "camera_xmeye"},
    34569: {"name": "XMEye backup/config", "group": "camera_xmeye"},
    #
    # Reolink-specific
    9000:  {"name": "Reolink media", "group": "camera_reolink"},
    32100: {"name": "Reolink P2P cloud", "group": "camera_cloud"},
    #
    # EZVIZ / Hik-Connect cloud
    19000: {"name": "EZVIZ P2P relay", "group": "camera_cloud"},
    9010:  {"name": "EZVIZ signal", "group": "camera_cloud"},
    #
    # Generic camera cloud / P2P relay
    6789:  {"name": "P2P cloud relay (generic)", "group": "camera_cloud"},
    8800:  {"name": "Cloud relay service", "group": "camera_cloud"},
    10000: {"name": "P2P relay (common)", "group": "camera_cloud"},
    10001: {"name": "P2P relay alt", "group": "camera_cloud"},
    15000: {"name": "Cloud broker (common)", "group": "camera_cloud"},
    20000: {"name": "Cloud video relay", "group": "camera_cloud"},
    #
    # Axis-specific
    2020:  {"name": "Axis ONVIF", "group": "camera_axis"},
    1900:  {"name": "SSDP/UPnP discovery", "group": "upnp"},
    #
    # Uniview-specific
    7788:  {"name": "Uniview SDK", "group": "camera_uniview"},
    7681:  {"name": "Uniview web stream", "group": "camera_uniview"},
    #
    # Generic camera / NVR
    8443:  {"name": "HTTPS-alt (camera/NVR web)", "group": "web"},
    8888:  {"name": "HTTP-alt (many cameras)", "group": "web"},
    85:    {"name": "HTTP-alt (cheap cameras)", "group": "camera"},
    81:    {"name": "HTTP-alt (common on cameras)", "group": "camera"},
    5050:  {"name": "Camera management (misc)", "group": "camera"},
    9080:  {"name": "Camera HTTP alt", "group": "camera"},
    #
    # ═══ NON-CAMERA PORTS ════════════════════════════════════════════
    #
    # Remote access
    22:    {"name": "SSH", "group": "remote"},
    23:    {"name": "Telnet", "group": "remote_insecure"},
    2323:  {"name": "Telnet-alt", "group": "remote_insecure"},
    3389:  {"name": "RDP", "group": "remote"},
    5900:  {"name": "VNC", "group": "remote"},
    # ESPHome / IoT
    6053:  {"name": "ESPHome native API", "group": "esphome"},
    # WLED
    21324: {"name": "WLED E1.31/sACN UDP", "group": "wled"},
    80:    {"name": "HTTP (WLED web UI)", "group": "web"},
    # Home Assistant
    8123:  {"name": "Home Assistant", "group": "ha"},
    # DNS
    53:    {"name": "DNS", "group": "network"},
    5353:  {"name": "mDNS/Bonjour", "group": "network"},
    # DHCP
    67:    {"name": "DHCP Server", "group": "network_risky"},
    # MQTT
    1883:  {"name": "MQTT", "group": "iot"},
    8883:  {"name": "MQTT-TLS", "group": "iot"},
    # Printing
    9100:  {"name": "RAW Print (JetDirect)", "group": "printer"},
    631:   {"name": "IPP/CUPS", "group": "printer"},
    515:   {"name": "LPD", "group": "printer"},
    # File sharing
    445:   {"name": "SMB", "group": "fileshare"},
    139:   {"name": "NetBIOS", "group": "fileshare"},
    21:    {"name": "FTP", "group": "fileshare_insecure"},
    2049:  {"name": "NFS", "group": "fileshare"},
    # NAS
    5000:  {"name": "Synology DSM / NAS web", "group": "nas"},
    5001:  {"name": "Synology DSM-TLS", "group": "nas"},
    8384:  {"name": "Syncthing", "group": "nas"},
    8080:  {"name": "QNAP QTS / HTTP-alt", "group": "web"},
    443:   {"name": "HTTPS / NAS-TLS", "group": "web"},
    6690:  {"name": "Synology Drive", "group": "nas"},
    5005:  {"name": "Synology WebDAV", "group": "nas"},
    5006:  {"name": "Synology WebDAV-TLS", "group": "nas"},
    8443:  {"name": "QNAP QTS-TLS / HTTPS-alt", "group": "web"},
    9090:  {"name": "TrueNAS / Cockpit", "group": "nas"},
    # Media servers
    32400: {"name": "Plex", "group": "media"},
    8096:  {"name": "Jellyfin", "group": "media"},
    8920:  {"name": "Jellyfin-TLS", "group": "media"},
    # Gaming
    3074:  {"name": "Xbox Live", "group": "gaming"},
    3478:  {"name": "PlayStation/STUN", "group": "gaming"},
    27015: {"name": "Steam", "group": "gaming"},
    # Crypto mining — Stratum protocol (pool connections)
    3333:  {"name": "Stratum v1 (mining pool)", "group": "crypto"},
    3334:  {"name": "Stratum v1-alt", "group": "crypto"},
    3335:  {"name": "Stratum v1-TLS", "group": "crypto"},
    4444:  {"name": "Stratum v1-alt2", "group": "crypto"},
    5555:  {"name": "Stratum (Monero common)", "group": "crypto"},
    7777:  {"name": "Stratum (ETC pool)", "group": "crypto"},
    8888:  {"name": "Stratum (multi-algo)", "group": "web"},
    9999:  {"name": "Stratum (NiceHash/alt)", "group": "crypto"},
    14433: {"name": "Stratum v2 (TLS)", "group": "crypto"},
    # Crypto mining — blockchain P2P
    8333:  {"name": "Bitcoin P2P", "group": "crypto"},
    8332:  {"name": "Bitcoin RPC", "group": "crypto"},
    18333: {"name": "Bitcoin Testnet", "group": "crypto"},
    9333:  {"name": "Litecoin P2P", "group": "crypto"},
    9332:  {"name": "Litecoin RPC", "group": "crypto"},
    30303: {"name": "Ethereum P2P (geth)", "group": "crypto"},
    30304: {"name": "Ethereum P2P-alt", "group": "crypto"},
    8545:  {"name": "Ethereum JSON-RPC", "group": "crypto"},
    8546:  {"name": "Ethereum WebSocket", "group": "crypto"},
    18080: {"name": "Monero P2P", "group": "crypto"},
    18081: {"name": "Monero RPC", "group": "crypto"},
    # Crypto mining — ASIC management
    4028:  {"name": "CGMiner/BFGMiner API", "group": "crypto"},
    4029:  {"name": "CGMiner API-alt", "group": "crypto"},
    8081:  {"name": "Antminer web UI", "group": "crypto"},
    # Crypto — Helium/IoT mining
    44158: {"name": "Helium Miner P2P", "group": "crypto"},
    4467:  {"name": "Helium gRPC", "group": "crypto"},
    # VPN
    1194:  {"name": "OpenVPN", "group": "vpn"},
    51820: {"name": "WireGuard", "group": "vpn"},
    # Email (outbound = suspicious on IoT)
    25:    {"name": "SMTP", "group": "email"},
    587:   {"name": "SMTP-submit", "group": "email"},
    # Database (should never be open on IoT)
    3306:  {"name": "MySQL", "group": "database"},
    5432:  {"name": "PostgreSQL", "group": "database"},
    6379:  {"name": "Redis", "group": "database"},
    27017: {"name": "MongoDB", "group": "database"},
    # Misc
    123:   {"name": "NTP", "group": "network"},
    161:   {"name": "SNMP", "group": "network"},
}

# ── Fingerprint rules ────────────────────────────────────────────────
# Each rule is: (required_groups, optional_groups, result_category,
#                result_description, confidence, risk_level)
# Checked in order; first match wins.

FINGERPRINT_RULES: list[tuple[set, set, str, str, str, str]] = [
    # ── CAMERA-SPECIFIC (highest priority) ──────────────────────────
    # Dahua with backdoor port
    ({"camera_dahua_backdoor"}, set(),
     "camera", "Dahua camera with DEBUG PORT 9530 OPEN — known backdoor (CVE-2017-7921, CVE-2021-36260). Quarantine immediately.",
     "high", "critical"),
    # XMEye/Xiongmai DVR
    ({"camera_xmeye"}, {"web"},
     "camera", "XMEye/Xiongmai DVR — actively phoning home on 34567/34568. CVE-2018-10088. Cloud can push firmware without consent. Mirai botnet primary target.",
     "high", "critical"),
    # Hikvision camera
    ({"camera_hik"}, {"camera", "web"},
     "camera", "Hikvision IP camera — SDK/ISAPI ports open. CVE-2021-36260 (RCE). Known to phone home to dev.hikvision.com / hik-connect.com.",
     "high", "high"),
    # Dahua camera
    ({"camera_dahua"}, {"camera", "web"},
     "camera", "Dahua IP camera/NVR — proprietary protocol ports 37777-37781 open. CVE-2021-33044/33045 (auth bypass).",
     "high", "high"),
    # Reolink
    ({"camera_reolink"}, {"camera", "web"},
     "camera", "Reolink camera — proprietary ports detected. Lower risk than Hikvision/Dahua but still phones home to reolink.com.",
     "high", "medium"),
    # Axis
    ({"camera_axis"}, {"camera", "web", "onvif"},
     "camera", "Axis camera — professional grade, ONVIF compliant. Better security than Chinese brands but still isolate.",
     "high", "low"),
    # Uniview
    ({"camera_uniview"}, {"camera", "web"},
     "camera", "Uniview camera — SDK port 7788 open. Chinese manufacturer, isolate to local-only.",
     "high", "high"),
    # Camera with cloud relay
    ({"camera_cloud"}, {"camera", "web"},
     "camera", "Camera with P2P cloud relay active — device is calling home to servers you don't control. Video may be accessible externally.",
     "high", "high"),
    # Camera with cloud relay but no RTSP (DVR/NVR only)
    ({"camera_cloud"}, set(),
     "camera", "P2P cloud relay active — this device is connecting to external servers. Likely a camera or DVR phoning home.",
     "high", "high"),
    # ONVIF-only (strong camera indicator)
    ({"onvif"}, {"web"},
     "camera", "ONVIF device detected — this is almost certainly an IP camera or NVR. ONVIF is the standard camera control protocol.",
     "high", "medium"),
    # RTSP-only (strong camera indicator)
    ({"camera"}, {"web"},
     "camera", "RTSP streaming port open — this is very likely an IP camera. RTSP is the standard video streaming protocol for cameras.",
     "medium", "medium"),
    # RTSP with nothing else
    ({"camera"}, set(),
     "camera", "RTSP port responding. Almost certainly a camera or media streaming device.",
     "medium", "medium"),
    # WLED device
    ({"wled"}, {"web"},
     "led", "WLED LED controller — E1.31/sACN port open, running WLED firmware",
     "high", "low"),
    # ESPHome device
    ({"esphome"}, {"web"},
     "esphome", "ESPHome device — native API port 6053 open, managed by Home Assistant",
     "high", "low"),
    # Home Assistant
    ({"ha"}, {"web"},
     "ha_device", "Home Assistant instance — web UI on port 8123",
     "high", "low"),
    # Printer
    ({"printer"}, {"web"},
     "printer", "Network printer — print service ports open (RAW/IPP/LPD)",
     "high", "low"),
    # NAS
    ({"nas"}, {"web", "fileshare"},
     "nas", "NAS/storage appliance — Synology/QNAP management ports detected",
     "high", "low"),
    # Media server
    ({"media"}, {"web"},
     "streaming", "Media server — Plex or Jellyfin streaming service detected",
     "high", "low"),
    # Crypto miner
    ({"crypto"}, set(),
     "crypto", "Crypto mining device — Stratum/blockchain P2P ports open. High bandwidth expected.",
     "high", "medium"),
    # Gaming
    ({"gaming"}, set(),
     "gaming", "Gaming device — Xbox Live, PlayStation, or Steam ports detected",
     "medium", "low"),
    # File server with insecure access
    ({"fileshare_insecure"}, {"fileshare"},
     "nas", "File server with INSECURE FTP open — consider disabling FTP and using SFTP",
     "medium", "medium"),
    # File sharing
    ({"fileshare"}, {"web"},
     "computer", "Device with file sharing — SMB/NFS ports open, likely a computer or NAS",
     "medium", "low"),
    # Insecure remote access
    ({"remote_insecure"}, set(),
     "iot", "Device with TELNET OPEN — insecure remote access, common IoT malware target. Quarantine recommended.",
     "high", "critical"),
    # Remote access (SSH/RDP/VNC)
    ({"remote"}, {"web"},
     "computer", "Device accepting remote connections — SSH, RDP, or VNC open",
     "medium", "low"),
    # MQTT broker
    ({"iot"}, {"web"},
     "iot", "IoT device or MQTT broker — messaging protocol ports detected",
     "medium", "low"),
    # VPN endpoint
    ({"vpn"}, set(),
     "networking", "VPN endpoint — OpenVPN or WireGuard tunnel",
     "medium", "low"),
    # Rogue DHCP
    ({"network_risky"}, set(),
     "networking", "ROGUE DHCP SERVER detected — this device is handing out IP addresses. Could hijack network traffic.",
     "high", "critical"),
    # UPnP
    ({"upnp"}, {"web"},
     "iot", "Device advertising via UPnP — can auto-open firewall holes. Consider disabling UPnP.",
     "low", "medium"),
    # Database exposed
    ({"database"}, set(),
     "computer", "DATABASE PORT EXPOSED — MySQL/PostgreSQL/Redis/MongoDB open to the network. Secure immediately.",
     "high", "critical"),
    # Email sending (suspicious on IoT)
    ({"email"}, set(),
     "iot", "Device with email ports open — could be a spam relay or exfiltrating data via email",
     "medium", "high"),
    # Web only
    ({"web"}, set(),
     "iot", "Device with web interface — could be a smart home device, router, or appliance",
     "low", "low"),
    # DNS only
    ({"network"}, set(),
     "networking", "Network infrastructure device — DNS/NTP/mDNS services",
     "low", "low"),
]

# ── Per-port vulnerability recommendations ───────────────────────────
# Shown when specific ports are found open.

_PORT_VULN_RECS: dict[int, str] = {
    21: "FTP (21): Credentials sent in PLAIN TEXT. Anyone on the network can sniff them. Block this port and use SFTP (port 22) instead.",
    23: "Telnet (23): CVE-rich, zero encryption. Mirai botnet scans for this port globally. Block it and use SSH. If the device only supports Telnet, quarantine it.",
    2323: "Telnet-alt (2323): Same risks as port 23. Commonly used by IoT malware to avoid basic port filters.",
    25: "SMTP (25): If this isn't a mail server, the device may be a spam relay or exfiltrating data. Block outbound port 25.",
    53: "DNS (53): If this isn't your router/Pi-hole, this device is running its own DNS — it could be redirecting lookups to malicious servers.",
    67: "DHCP Server (67): ROGUE DHCP — this device is handing out IP addresses. It can redirect all traffic through itself (MITM). Quarantine unless this is your router.",
    80: "HTTP (80): Unencrypted web UI. Login credentials are visible on the network. Access the HTTPS version (443) instead if available.",
    139: "NetBIOS (139): Legacy Windows protocol with known vulnerabilities (EternalBlue, WannaCry). Block unless you specifically need LAN file sharing with old devices.",
    161: "SNMP (161): If using default community strings (public/private), anyone can read device config. Change community strings or disable SNMPv1/v2.",
    445: "SMB (445): Windows file sharing — target of EternalBlue (MS17-010), WannaCry, NotPetya. Ensure SMBv1 is disabled. Block if the device doesn't need file sharing.",
    554: "RTSP (554): Video stream is unencrypted by default. Anyone on the network can view the camera feed. OK for local-only use, dangerous if internet-exposed.",
    1883: "MQTT (1883): Unencrypted IoT messaging. If no auth is configured, anyone can read/write messages. Use MQTT-TLS (8883) with authentication instead.",
    1900: "UPnP (1900): Can auto-open firewall ports without your knowledge. Disable UPnP on your router and on this device.",
    3306: "MySQL (3306): Database exposed to the network. Should NEVER be accessible from other devices. Bind to 127.0.0.1 and use SSH tunnels for remote access.",
    3389: "RDP (3389): Remote Desktop. Major attack surface (BlueKeep CVE-2019-0708). Ensure NLA is enabled, use a VPN instead of exposing RDP directly.",
    5432: "PostgreSQL (5432): Database exposed. Bind to localhost, use pg_hba.conf to restrict connections, and never use default passwords.",
    5900: "VNC (5900): Remote desktop with weak or no encryption. Many VNC servers have no authentication by default. Use SSH tunneling or a VPN.",
    6379: "Redis (6379): Key-value database. Default config has NO PASSWORD and binds to all interfaces. Attackers use this for cryptocurrency mining. Secure immediately.",
    8080: "HTTP-alt (8080): Common for camera/router web UIs. Check if default credentials are still set (admin/admin is common).",
    8443: "HTTPS-alt (8443): Often used for management consoles. Verify SSL certificate is valid and default credentials are changed.",
    9100: "RAW Print (9100): Printers on this port can be hijacked to print anything. Also potential lateral movement vector. Isolate printers on their own VLAN.",
    9530: "Dahua Debug (9530): KNOWN BACKDOOR in Dahua cameras (CVE-2017-7921, CVE-2021-36260). Allows unauthenticated remote access. Block this port IMMEDIATELY and update firmware.",
    27017: "MongoDB (27017): Default install has NO authentication. Thousands of MongoDB databases have been ransomed. Enable auth and bind to localhost.",
    34567: "XMEye (34567): Xiongmai/XMEye DVR cloud protocol. CVE-2018-10088 allows unauthenticated access. These devices are known to phone home to Chinese servers. Block or quarantine.",
    34568: "XMEye Media (34568): XMEye video streaming port. Combined with 34567, confirms an actively communicating Chinese DVR.",
    37777: "Dahua TCP (37777): Dahua camera/NVR management. Check firmware is up to date — multiple critical CVEs (CVE-2021-36260 remote code execution).",
}

# ── No ports open at all
NO_PORTS_RESULT = {
    "category": "unknown",
    "description": "No scanned ports responded. Device may be a passive client (phone, tablet), behind a firewall, or powered off.",
    "confidence": "low",
    "risk": "unknown",
}

# Add crypto port vulnerability recommendations.
_PORT_VULN_RECS.update({
    3333: "Stratum (3333): Mining pool connection. If you don't own a miner, a device may be cryptojacking — mining for an attacker. Investigate immediately.",
    4444: "Stratum-alt (4444): Alternative mining pool port. Same risk as 3333.",
    4028: "CGMiner API (4028): Miner management API with NO authentication by default. Anyone on your network can change pool settings and steal hashrate.",
    8332: "Bitcoin RPC (8332): Bitcoin node RPC interface. Should be password-protected and bound to localhost.",
    8333: "Bitcoin P2P (8333): This device is running a Bitcoin node. High bandwidth usage expected.",
    8545: "Ethereum RPC (8545): Ethereum node JSON-RPC. If exposed without auth, attackers can drain wallets. Bind to localhost only.",
    18080: "Monero P2P (18080): Monero node. Monero is the preferred cryptocurrency for cryptojacking due to CPU-friendly mining.",
    18081: "Monero RPC (18081): Monero RPC interface. Restrict access.",
    30303: "Ethereum P2P (30303): Ethereum node peer-to-peer. High bandwidth and storage usage.",
    44158: "Helium P2P (44158): Helium IoT miner. Legitimate if you own it, but verify it's earning to YOUR wallet.",
})


SCAN_CACHE_FILE = "unifiblocker_scan_cache.json"


class PortScanner:
    """Async TCP port scanner with fingerprinting. Cache persists to disk."""

    def __init__(self, hass=None) -> None:
        self._cache: dict[str, dict[str, Any]] = {}
        self._scanning: set[str] = set()
        self._hass = hass
        self._cache_path = None
        if hass:
            import os
            self._cache_path = os.path.join(hass.config.config_dir, SCAN_CACHE_FILE)
            self._load_cache()

    def _load_cache(self) -> None:
        """Load cached scan results from disk."""
        if not self._cache_path:
            return
        try:
            import json, os
            if os.path.exists(self._cache_path):
                with open(self._cache_path, "r") as f:
                    self._cache = json.load(f)
                _LOGGER.info("Loaded %d cached scan results", len(self._cache))
        except Exception:
            _LOGGER.debug("No scan cache found", exc_info=True)

    def _save_cache(self) -> None:
        """Persist scan cache to disk (run in executor)."""
        if not self._cache_path:
            return
        try:
            import json
            with open(self._cache_path, "w") as f:
                json.dump(self._cache, f)
        except Exception:
            _LOGGER.debug("Could not save scan cache", exc_info=True)

    async def _async_save_cache(self) -> None:
        """Save cache to disk without blocking the event loop."""
        if self._hass and self._cache_path:
            await self._hass.async_add_executor_job(self._save_cache)

    @property
    def cache(self) -> dict[str, dict[str, Any]]:
        return self._cache

    def get_result(self, mac: str) -> dict[str, Any] | None:
        return self._cache.get(mac.lower())

    async def scan_device(self, ip: str, mac: str) -> dict[str, Any]:
        """Scan a single device and return fingerprint results."""
        mac = mac.lower()

        # Check cooldown.
        cached = self._cache.get(mac)
        if cached and time.time() - cached.get("scan_time", 0) < SCAN_COOLDOWN:
            return cached

        if mac in self._scanning:
            return cached or {"status": "already_scanning"}

        self._scanning.add(mac)
        _LOGGER.info("Port scanning %s (%s)...", ip, mac)

        try:
            open_ports = await self._tcp_scan(ip)
            result = self._fingerprint(open_ports, mac)
            result["ip"] = ip
            result["mac"] = mac
            result["scan_time"] = time.time()
            result["status"] = "complete"
            self._cache[mac] = result
            # Persist to disk so results survive restarts.
            try:
                await self._async_save_cache()
            except Exception:
                pass
            _LOGGER.info(
                "Scan complete for %s: %d open ports, guess=%s (%s confidence)",
                ip, len(open_ports), result.get("guess_category", "?"),
                result.get("guess_confidence", "?"),
            )
            return result
        except Exception as err:
            _LOGGER.warning("Scan failed for %s: %s", ip, err)
            return {"status": "error", "error": str(err), "mac": mac, "ip": ip}
        finally:
            self._scanning.discard(mac)

    async def scan_multiple(self, targets: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
        """Scan multiple devices. *targets* is a list of {"ip": ..., "mac": ...}."""
        results = {}
        # Scan sequentially to avoid overwhelming the network.
        for t in targets:
            ip = t.get("ip", "")
            mac = t.get("mac", "")
            if ip and mac:
                results[mac.lower()] = await self.scan_device(ip, mac)
        return results

    # ── TCP scanner ──────────────────────────────────────────────────

    async def _tcp_scan(self, ip: str) -> list[int]:
        """Return list of open TCP ports on *ip*."""
        ports = list(SCAN_PORTS.keys())
        open_ports: list[int] = []
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def check(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=CONNECT_TIMEOUT,
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(port)
                except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                    pass

        await asyncio.gather(*(check(p) for p in ports))
        open_ports.sort()
        return open_ports

    # ── Fingerprinting ───────────────────────────────────────────────

    def _fingerprint(self, open_ports: list[int], mac: str) -> dict[str, Any]:
        """Analyze open ports and produce a fingerprint report."""
        if not open_ports:
            return {
                "open_ports": [],
                "port_details": [],
                "groups_found": [],
                "guess_category": NO_PORTS_RESULT["category"],
                "guess_description": NO_PORTS_RESULT["description"],
                "guess_confidence": NO_PORTS_RESULT["confidence"],
                "guess_risk": NO_PORTS_RESULT["risk"],
                "warnings": [],
                "recommendations": [],
            }

        # Build port details and group set.
        port_details = []
        groups: set[str] = set()
        for port in open_ports:
            info = SCAN_PORTS.get(port, {"name": f"Port {port}", "group": "unknown"})
            port_details.append({
                "port": port,
                "name": info["name"],
                "group": info["group"],
            })
            groups.add(info["group"])

        # Match against fingerprint rules.
        guess_cat = "unknown"
        guess_desc = "Could not determine device type from open ports alone."
        guess_conf = "low"
        guess_risk = "unknown"

        for required, optional, cat, desc, conf, risk in FINGERPRINT_RULES:
            if required.issubset(groups):
                guess_cat = cat
                guess_desc = desc
                guess_conf = conf
                guess_risk = risk
                break

        # Generate warnings.
        warnings = []
        if "remote_insecure" in groups:
            warnings.append("TELNET is open — this is an insecure protocol. Attackers and botnets (Mirai) actively scan for this.")
        if "camera_dahua_backdoor" in groups:
            warnings.append("Dahua debug port 9530 is OPEN — this is a known backdoor. Block or quarantine this device immediately.")
        if "camera_xmeye" in groups:
            warnings.append("XMEye ports 34567/34568 are open — this DVR is actively communicating with Chinese cloud servers.")
        if "camera_cloud" in groups:
            warnings.append("Camera P2P cloud relay port detected — the camera is phoning home to a remote server you don't control.")
        if "database" in groups:
            warnings.append("Database port exposed to the network — should be firewalled or bound to localhost only.")
        if "network_risky" in groups:
            warnings.append("DHCP server port open — if this isn't your router, this is a rogue DHCP server that could hijack network traffic.")
        if "email" in groups:
            warnings.append("SMTP port open — unusual for IoT. Could be sending spam or exfiltrating data via email.")
        if "fileshare_insecure" in groups:
            warnings.append("FTP is open — unencrypted file transfer. Credentials and data are sent in plain text.")
        if 1900 in open_ports:
            warnings.append("UPnP is active — this can automatically open holes in your firewall without your knowledge.")

        # Generate recommendations.
        recommendations = []
        if guess_risk == "critical":
            recommendations.append("QUARANTINE this device immediately — it poses an active security risk.")
        if "camera_cloud" in groups or "camera_xmeye" in groups:
            recommendations.append("Move to Local-Only subnet (192.168.2.x) to block all internet access while keeping local streaming.")
        if "camera" in groups and "camera_cloud" not in groups:
            recommendations.append("Consider moving to Local-Only subnet as a precaution — cameras don't need internet for local viewing.")
        if "remote_insecure" in groups:
            recommendations.append("Disable Telnet on this device and use SSH instead. If you can't disable it, quarantine the device.")
        if "database" in groups:
            recommendations.append("Bind the database to localhost only, or firewall it to allow only specific IPs.")
        if guess_risk in ("low", "unknown") and guess_cat != "unknown":
            recommendations.append(f"This appears to be a {guess_cat} device. Review and mark as Trusted if you recognize it.")
        if guess_cat == "unknown" and open_ports:
            recommendations.append("Ports are open but device type is unclear. Check the manufacturer's documentation or try accessing the web UI if ports 80/443 are open.")

        # Per-port vulnerability recommendations.
        for port in open_ports:
            rec = _PORT_VULN_RECS.get(port)
            if rec:
                recommendations.append(rec)

        return {
            "open_ports": open_ports,
            "port_details": port_details,
            "groups_found": sorted(groups),
            "guess_category": guess_cat,
            "guess_description": guess_desc,
            "guess_confidence": guess_conf,
            "guess_risk": guess_risk,
            "warnings": warnings,
            "recommendations": recommendations,
        }
