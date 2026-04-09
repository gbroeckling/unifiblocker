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
    # Web interfaces
    80:    {"name": "HTTP", "group": "web"},
    443:   {"name": "HTTPS", "group": "web"},
    8080:  {"name": "HTTP-alt", "group": "web"},
    8443:  {"name": "HTTPS-alt", "group": "web"},
    8888:  {"name": "HTTP-alt2", "group": "web"},
    3000:  {"name": "Dev/Grafana", "group": "web"},
    # Camera — Hikvision
    554:   {"name": "RTSP", "group": "camera"},
    8000:  {"name": "Hikvision SDK", "group": "camera_hik"},
    8200:  {"name": "Hikvision ISAPI", "group": "camera_hik"},
    9527:  {"name": "Hikvision SDK2", "group": "camera_hik"},
    # Camera — Dahua
    37777: {"name": "Dahua TCP", "group": "camera_dahua"},
    37778: {"name": "Dahua UDP-TCP", "group": "camera_dahua"},
    9530:  {"name": "Dahua Debug", "group": "camera_dahua_backdoor"},
    # Camera — XMEye
    34567: {"name": "XMEye Control", "group": "camera_xmeye"},
    34568: {"name": "XMEye Media", "group": "camera_xmeye"},
    # Camera — general
    1935:  {"name": "RTMP", "group": "camera"},
    8554:  {"name": "RTSP-alt", "group": "camera"},
    8555:  {"name": "RTSP-alt2", "group": "camera"},
    6000:  {"name": "ONVIF/X11", "group": "camera"},
    # Camera — cloud phone-home
    6789:  {"name": "P2P Cloud", "group": "camera_cloud"},
    32100: {"name": "Reolink P2P", "group": "camera_cloud"},
    19000: {"name": "EZVIZ P2P", "group": "camera_cloud"},
    8800:  {"name": "Cloud Relay", "group": "camera_cloud"},
    # Remote access
    22:    {"name": "SSH", "group": "remote"},
    23:    {"name": "Telnet", "group": "remote_insecure"},
    2323:  {"name": "Telnet-alt", "group": "remote_insecure"},
    3389:  {"name": "RDP", "group": "remote"},
    5900:  {"name": "VNC", "group": "remote"},
    # ESPHome / IoT
    6053:  {"name": "ESPHome API", "group": "esphome"},
    # Home Assistant
    8123:  {"name": "Home Assistant", "group": "ha"},
    # DNS
    53:    {"name": "DNS", "group": "network"},
    5353:  {"name": "mDNS", "group": "network"},
    # DHCP
    67:    {"name": "DHCP Server", "group": "network_risky"},
    # MQTT
    1883:  {"name": "MQTT", "group": "iot"},
    8883:  {"name": "MQTT-TLS", "group": "iot"},
    # Printing
    9100:  {"name": "RAW Print", "group": "printer"},
    631:   {"name": "IPP/CUPS", "group": "printer"},
    515:   {"name": "LPD", "group": "printer"},
    # File sharing
    445:   {"name": "SMB", "group": "fileshare"},
    139:   {"name": "NetBIOS", "group": "fileshare"},
    21:    {"name": "FTP", "group": "fileshare_insecure"},
    2049:  {"name": "NFS", "group": "fileshare"},
    # NAS
    5000:  {"name": "Synology DSM", "group": "nas"},
    5001:  {"name": "Synology DSM-TLS", "group": "nas"},
    8384:  {"name": "Syncthing", "group": "nas"},
    # Media servers
    32400: {"name": "Plex", "group": "media"},
    8096:  {"name": "Jellyfin", "group": "media"},
    8920:  {"name": "Jellyfin-TLS", "group": "media"},
    # UPnP
    1900:  {"name": "SSDP/UPnP", "group": "upnp"},
    5000:  {"name": "UPnP Media", "group": "upnp"},
    # Gaming
    3074:  {"name": "Xbox Live", "group": "gaming"},
    3478:  {"name": "PlayStation", "group": "gaming"},
    27015: {"name": "Steam", "group": "gaming"},
    # Crypto mining
    3333:  {"name": "Stratum Mining", "group": "crypto"},
    4444:  {"name": "Stratum-alt", "group": "crypto"},
    8333:  {"name": "Bitcoin P2P", "group": "crypto"},
    9333:  {"name": "Litecoin P2P", "group": "crypto"},
    30303: {"name": "Ethereum P2P", "group": "crypto"},
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
    # Hikvision camera
    ({"camera_hik"}, {"camera", "web"},
     "camera", "Hikvision IP camera — SDK port open, likely phoning home via cloud",
     "high", "high"),
    # Dahua camera
    ({"camera_dahua"}, {"camera", "web"},
     "camera", "Dahua IP camera — DVR/NVR protocol ports open",
     "high", "high"),
    # Dahua with backdoor port
    ({"camera_dahua_backdoor"}, set(),
     "camera", "Dahua camera with DEBUG PORT 9530 OPEN — known backdoor, quarantine immediately",
     "high", "critical"),
    # XMEye/Xiongmai DVR
    ({"camera_xmeye"}, {"web"},
     "camera", "XMEye/Xiongmai DVR — Chinese DVR actively phoning home on ports 34567/34568",
     "high", "critical"),
    # Camera with cloud relay
    ({"camera_cloud"}, {"camera", "web"},
     "camera", "Camera with P2P cloud relay active — device is calling home to remote servers",
     "high", "high"),
    # Generic camera (RTSP open)
    ({"camera"}, {"web"},
     "camera", "IP camera — RTSP streaming port open. Check if it also phones home.",
     "medium", "medium"),
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


class PortScanner:
    """Async TCP port scanner with fingerprinting."""

    def __init__(self) -> None:
        # mac → {scan result}
        self._cache: dict[str, dict[str, Any]] = {}
        self._scanning: set[str] = set()

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
