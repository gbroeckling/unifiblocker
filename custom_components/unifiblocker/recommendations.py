"""Security recommendation engine.

Analyzes each device's vendor, category, open ports, traffic patterns,
network placement, and state to generate prioritized, actionable
security recommendations.

Built from community consensus (r/homelab, r/unifi, r/homeassistant),
CVE databases, and IoT security research.
"""
from __future__ import annotations

from typing import Any

# ── Known-vulnerable vendors and their issues ────────────────────────

VENDOR_ADVISORIES: dict[str, dict[str, Any]] = {
    "Hikvision": {
        "risk": "high",
        "cves": ["CVE-2021-36260 (RCE)", "CVE-2017-7921 (auth bypass)", "CVE-2023-6895 (cmd injection)"],
        "phone_home": ["dev.hikvision.com", "api.hikvision.com", "hik-connect.com", "ezvizlife.com"],
        "advice": "Assume compromised. Isolate to local-only subnet. Disable Platform Access in camera settings. Update firmware via manual download, never auto-update.",
    },
    "Dahua": {
        "risk": "high",
        "cves": ["CVE-2021-33044 (auth bypass)", "CVE-2021-33045 (auth bypass)", "CVE-2021-36260 (RCE)"],
        "phone_home": ["easy4ip.com", "cloud-service.dahuatech.com", "dahuasecurity.com", "imoulife.com"],
        "advice": "Known authentication bypass vulnerabilities. Isolate completely. Disable P2P/cloud in Network settings. Check for port 9530 (debug backdoor).",
    },
    "XMEye/Xiongmai": {
        "risk": "critical",
        "cves": ["CVE-2018-10088 (buffer overflow RCE)", "Mirai botnet primary target"],
        "phone_home": ["xmeye.net", "xmcsrv.net", "nseye.com", "eseecloud.com", "meye.net"],
        "advice": "HIGHEST RISK. Cloud account cannot be fully disabled. Firmware update mechanism controlled by cloud without user consent. Quarantine or replace. These were the primary Mirai botnet devices.",
    },
    "Reolink": {
        "risk": "medium",
        "phone_home": ["reolink.com", "reolink.cloud"],
        "cves": [],
        "advice": "Better security posture than Hikvision/Dahua, but still phones home. Isolate to local-only subnet. RTSP/ONVIF work fully without internet.",
    },
    "EZVIZ": {
        "risk": "high",
        "phone_home": ["ezvizlife.com", "ezviz7.com"],
        "cves": ["Same underlying firmware as Hikvision"],
        "advice": "EZVIZ is Hikvision's consumer brand. Same vulnerabilities apply. Isolate completely.",
    },
    "Imou": {
        "risk": "high",
        "phone_home": ["imoulife.com", "easy4ip.com"],
        "cves": ["Same underlying firmware as Dahua"],
        "advice": "Imou is Dahua's consumer brand. Same vulnerabilities apply. Isolate completely.",
    },
    "Foscam": {
        "risk": "high",
        "phone_home": ["foscam.com", "myfoscam.com"],
        "cves": ["Multiple historical auth bypass and RCE vulnerabilities"],
        "advice": "Historical track record of severe vulnerabilities. Isolate and consider replacing.",
    },
}

# ── Recommendation categories ───────────────────────────────────────

PRIORITY_CRITICAL = "critical"
PRIORITY_HIGH = "high"
PRIORITY_MEDIUM = "medium"
PRIORITY_LOW = "low"
PRIORITY_INFO = "info"

PRIORITY_LABELS = {
    PRIORITY_CRITICAL: "🔴 CRITICAL",
    PRIORITY_HIGH: "🟠 HIGH",
    PRIORITY_MEDIUM: "🟡 MEDIUM",
    PRIORITY_LOW: "🟢 LOW",
    PRIORITY_INFO: "ℹ️ INFO",
}


def generate_recommendations(device: dict[str, Any]) -> list[dict[str, Any]]:
    """Generate prioritized recommendations for a single device.

    *device* is an enriched client dict from the coordinator.

    Returns a list of recommendation dicts, sorted by priority::

        {
            "priority": "critical",
            "priority_label": "🔴 CRITICAL",
            "title": "...",
            "detail": "...",
            "action": "quarantine" | "local_only" | "block_port" | "review" | "info",
            "action_data": {...},
        }
    """
    recs: list[dict[str, Any]] = []
    vendor = device.get("vendor", "")
    category = device.get("category", "unknown")
    state = device.get("state", "new")
    is_camera = device.get("is_camera", False)
    suspicious = device.get("suspicious", False)
    threat_level = device.get("threat_level", "none")
    mac = device.get("mac", "")
    ip = device.get("ip", "")
    hostname = device.get("hostname", "")
    flags = device.get("suspicion_flags", [])
    scan = device.get("scan_result", {})
    open_ports = scan.get("open_ports", [])

    # ── 1. Vendor-specific advisories ────────────────────────────────

    advisory = VENDOR_ADVISORIES.get(vendor)
    if advisory:
        risk = advisory["risk"]
        pri = PRIORITY_CRITICAL if risk == "critical" else PRIORITY_HIGH
        cve_text = ", ".join(advisory["cves"]) if advisory["cves"] else "Check vendor CVE history"
        domains = ", ".join(advisory["phone_home"][:3])
        recs.append({
            "priority": pri,
            "priority_label": PRIORITY_LABELS[pri],
            "title": f"{vendor} — known security concerns",
            "detail": f"{advisory['advice']}\n\nKnown CVEs: {cve_text}\nPhones home to: {domains}",
            "action": "local_only" if risk != "critical" else "quarantine",
            "action_data": {"mac": mac},
        })

    # ── 2. Camera on main network ────────────────────────────────────

    if is_camera and ip and not ip.startswith("192.168.2."):
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Camera on main network — not isolated",
            "detail": "This camera is on your main network and can reach other devices and the internet. "
                      "Move it to the local-only subnet (192.168.2.x) to block internet access while "
                      "keeping local RTSP/ONVIF streaming. Cameras don't need internet for local recording.",
            "action": "local_only",
            "action_data": {"mac": mac, "category": "camera"},
        })

    # ── 3. Suspicious traffic flags ──────────────────────────────────

    if suspicious and threat_level in ("high", "medium"):
        recs.append({
            "priority": PRIORITY_HIGH if threat_level == "high" else PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH if threat_level == "high" else PRIORITY_MEDIUM],
            "title": f"Suspicious behavior detected (score: {device.get('suspicion_score', 0)})",
            "detail": "Flags: " + "; ".join(flags) if flags else "Multiple behavioral indicators triggered.",
            "action": "review",
            "action_data": {"mac": mac},
        })

    # ── 4. Port-based recommendations ────────────────────────────────

    if 23 in open_ports or 2323 in open_ports:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": "Telnet is OPEN — Mirai botnet target",
            "detail": "Telnet has zero encryption. The Mirai botnet (2016) compromised 600,000+ devices "
                      "by scanning for open Telnet ports with default credentials. Block this port immediately "
                      "and use SSH (port 22) instead. If the device only supports Telnet, quarantine it.",
            "action": "block_port",
            "action_data": {"mac": mac, "ports": [23, 2323]},
        })

    if 9530 in open_ports:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": "Dahua debug port 9530 OPEN — known backdoor",
            "detail": "CVE-2017-7921 / CVE-2021-36260. This port allows unauthenticated remote access. "
                      "Attackers can view camera feeds, extract credentials, and execute commands. "
                      "Block this port AND quarantine the device until firmware is updated.",
            "action": "quarantine",
            "action_data": {"mac": mac},
        })

    if 34567 in open_ports or 34568 in open_ports:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": "XMEye cloud ports active — phoning home to China",
            "detail": "Ports 34567/34568 are the XMEye/Xiongmai cloud protocol. This device is actively "
                      "communicating with Chinese cloud servers. CVE-2018-10088 allows unauthenticated "
                      "remote access. The cloud can push firmware updates without your consent. "
                      "Move to local-only subnet or quarantine.",
            "action": "local_only",
            "action_data": {"mac": mac, "category": "camera"},
        })

    if any(p in open_ports for p in [6789, 32100, 19000, 8800]):
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "P2P cloud relay port active",
            "detail": "This device is using a P2P cloud relay to maintain a connection to an external server. "
                      "This allows remote access to the device from the manufacturer's app, but it also means "
                      "your video feed passes through servers you don't control. Block these ports or move to local-only.",
            "action": "block_port",
            "action_data": {"mac": mac, "ports": [p for p in [6789, 32100, 19000, 8800] if p in open_ports]},
        })

    if 445 in open_ports or 139 in open_ports:
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": "SMB/NetBIOS file sharing open",
            "detail": "SMB (port 445) was the attack vector for EternalBlue (MS17-010), WannaCry, and NotPetya. "
                      "Ensure SMBv1 is disabled. If this device doesn't need file sharing, block these ports.",
            "action": "block_port",
            "action_data": {"mac": mac, "ports": [p for p in [445, 139] if p in open_ports]},
        })

    if 67 in open_ports:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": "ROGUE DHCP SERVER detected",
            "detail": "This device has DHCP server port 67 open. Unless this is your router, it's handing "
                      "out IP addresses and could redirect all network traffic through itself (man-in-the-middle). "
                      "Quarantine immediately.",
            "action": "quarantine",
            "action_data": {"mac": mac},
        })

    if any(p in open_ports for p in [3306, 5432, 6379, 27017]):
        db_ports = [p for p in [3306, 5432, 6379, 27017] if p in open_ports]
        db_names = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
        names = [db_names.get(p, str(p)) for p in db_ports]
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": f"Database exposed: {', '.join(names)}",
            "detail": "Database ports should NEVER be accessible from other devices on the network. "
                      "Redis and MongoDB have no authentication by default. Bind to 127.0.0.1 and use "
                      "SSH tunnels for remote access. Thousands of exposed databases have been ransomed.",
            "action": "block_port",
            "action_data": {"mac": mac, "ports": db_ports},
        })

    if 1900 in open_ports:
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": "UPnP is active",
            "detail": "UPnP can automatically open ports on your router's firewall without your knowledge. "
                      "Disable UPnP on this device and on your router (UniFi: Settings → Security → disable UPnP).",
            "action": "info",
            "action_data": {},
        })

    # ── 5. State-based recommendations ───────────────────────────────

    if state == "new":
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": "Unreviewed device — classify it",
            "detail": "This device hasn't been reviewed yet. Scan its ports, check the vendor, and decide: "
                      "Trust (known device), Ignore (don't care), or Quarantine (suspicious).",
            "action": "review",
            "action_data": {"mac": mac},
        })

    # ── 6. Crypto miner recommendations ────────────────────────────

    if category == "crypto":
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Crypto miner detected",
            "detail": "This device appears to be a cryptocurrency miner. Miners use significant "
                      "electricity and bandwidth. If unauthorized, quarantine immediately.\n\n"
                      "If this is YOUR miner:\n"
                      "- Isolate to its own subnet or VLAN\n"
                      "- Monitor power consumption\n"
                      "- Ensure firmware is up to date (ASIC miners are frequent hack targets)\n"
                      "- Change default web UI password (Antminer default: root/root)\n"
                      "- Disable remote management ports if not needed\n"
                      "- Check pool settings — unauthorized miners redirect hashrate to attacker pools",
            "action": "review",
            "action_data": {"mac": mac},
        })

    if any(p in open_ports for p in [3333, 3334, 4444, 5555, 7777, 9999, 14433]):
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Stratum mining pool port open",
            "detail": "This device has a Stratum mining protocol port open, indicating active "
                      "cryptocurrency mining. If you don't own a miner, a device on your network "
                      "may be compromised and mining crypto for an attacker (cryptojacking).",
            "action": "review",
            "action_data": {"mac": mac},
        })

    if any(p in open_ports for p in [4028, 4029]):
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": "CGMiner/BFGMiner API exposed",
            "detail": "The miner management API is accessible from the network. Anyone on your "
                      "LAN can change pool settings, redirect hashrate, or modify miner config. "
                      "Restrict access to trusted IPs only.",
            "action": "block_port",
            "action_data": {"mac": mac, "ports": [4028, 4029]},
        })

    # ── 7. General best practices ────────────────────────────────────

    if is_camera and 80 in open_ports and 443 not in open_ports:
        recs.append({
            "priority": PRIORITY_LOW,
            "priority_label": PRIORITY_LABELS[PRIORITY_LOW],
            "title": "Camera web UI is HTTP-only (unencrypted)",
            "detail": "Login credentials are sent in plain text. Anyone on the network can see them. "
                      "Check if the camera supports HTTPS and enable it.",
            "action": "info",
            "action_data": {},
        })

    if is_camera:
        recs.append({
            "priority": PRIORITY_INFO,
            "priority_label": PRIORITY_LABELS[PRIORITY_INFO],
            "title": "Camera best practices checklist",
            "detail": "1. Change default password (admin/admin is common)\n"
                      "2. Disable P2P/cloud in camera settings\n"
                      "3. Disable Telnet, FTP, SNMP if present\n"
                      "4. Disable UPnP in camera settings\n"
                      "5. Set NTP to your local router IP\n"
                      "6. Use substream for NVR detection, mainstream for recording\n"
                      "7. Update firmware from manufacturer's site (not auto-update)",
            "action": "info",
            "action_data": {},
        })

    if category == "iot" and state != "trusted":
        recs.append({
            "priority": PRIORITY_LOW,
            "priority_label": PRIORITY_LABELS[PRIORITY_LOW],
            "title": "IoT device — consider isolation",
            "detail": "IoT devices often have weak security and receive infrequent updates. "
                      "Consider moving to the local-only subnet if it doesn't need internet access.",
            "action": "local_only",
            "action_data": {"mac": mac, "category": category},
        })

    # Sort by priority.
    priority_order = {PRIORITY_CRITICAL: 0, PRIORITY_HIGH: 1, PRIORITY_MEDIUM: 2, PRIORITY_LOW: 3, PRIORITY_INFO: 4}
    recs.sort(key=lambda r: priority_order.get(r["priority"], 5))

    return recs


def generate_network_recommendations(
    devices: list[dict[str, Any]],
    firewall_exists: bool = False,
) -> list[dict[str, Any]]:
    """Generate network-wide security recommendations."""
    recs: list[dict[str, Any]] = []

    cameras = [d for d in devices if d.get("is_camera")]
    cameras_on_main = [d for d in cameras if not d.get("ip", "").startswith("192.168.2.")]
    new_count = sum(1 for d in devices if d.get("state") == "new")
    telnet_devices = [d for d in devices if 23 in (d.get("scan_result", {}).get("open_ports", []))]

    if not firewall_exists:
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Local-only firewall rule not created",
            "detail": "The firewall rule blocking 192.168.2.0/24 from WAN hasn't been created yet. "
                      "Go to the Local Only view and click 'Create Firewall Rule'. Without this, "
                      "devices on the local-only subnet can still reach the internet.",
            "action": "info",
            "action_data": {},
        })

    if cameras_on_main:
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": f"{len(cameras_on_main)} camera(s) on main network",
            "detail": "These cameras can reach the internet and all other devices on your network. "
                      f"MACs: {', '.join(d.get('mac','') for d in cameras_on_main[:5])}. "
                      "Move them to the local-only subnet (192.168.2.x).",
            "action": "info",
            "action_data": {},
        })

    if new_count > 10:
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": f"{new_count} unreviewed devices",
            "detail": "You have many unclassified devices. Review them in the New Devices or Identify view. "
                      "Port scan unknown devices to help determine what they are.",
            "action": "info",
            "action_data": {},
        })

    if telnet_devices:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": f"{len(telnet_devices)} device(s) with Telnet open",
            "detail": "Telnet is the #1 attack vector for IoT botnets. Block port 23 on these devices immediately.",
            "action": "info",
            "action_data": {},
        })

    # General hardening
    recs.append({
        "priority": PRIORITY_INFO,
        "priority_label": PRIORITY_LABELS[PRIORITY_INFO],
        "title": "Network hardening checklist",
        "detail": "1. Disable UPnP on router (UniFi: Settings → Security)\n"
                  "2. Enable IDS/IPS on UCG Max (Settings → Security → Threat Management)\n"
                  "3. Redirect all DNS (port 53) from IoT devices to your local DNS server\n"
                  "4. Disable IPv6 on camera/IoT networks (prevents IPv6 internet bypass)\n"
                  "5. Run a local NTP server for isolated devices\n"
                  "6. Use VPN for remote access instead of port forwarding\n"
                  "7. Review firewall logs regularly for blocked connection attempts\n"
                  "8. Consider Pi-hole/AdGuard for DNS-level blocking (supplementary layer)",
        "action": "info",
        "action_data": {},
    })

    priority_order = {PRIORITY_CRITICAL: 0, PRIORITY_HIGH: 1, PRIORITY_MEDIUM: 2, PRIORITY_LOW: 3, PRIORITY_INFO: 4}
    recs.sort(key=lambda r: priority_order.get(r["priority"], 5))
    return recs
