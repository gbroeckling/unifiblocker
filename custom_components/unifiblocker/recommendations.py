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
        "cves": ["CVE-2021-33044 (auth bypass)", "CVE-2021-33045 (auth bypass)"],
        "phone_home": ["easy4ip.com", "cloud-service.dahuatech.com", "dahuasecurity.com", "imoulife.com"],
        "advice": "Known authentication bypass vulnerabilities. Isolate completely. Disable P2P/cloud in Network settings. Check for port 9530 (debug backdoor).",
    },
    "XMEye/Xiongmai": {
        "risk": "critical",
        "cves": ["CVE-2018-10088 (buffer overflow RCE)", "Mirai botnet primary target"],
        "phone_home": ["xmeye.net", "xmcsrv.net", "secu100.net", "nseye.com", "eseecloud.com", "meye.net"],
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

# UniFi reports the full IEEE owner ("Hangzhou Hikvision Digital Technology
# Co.,Ltd."), so match on keywords. EZVIZ/Imou come before their parents.
_ADVISORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("EZVIZ", ("ezviz",)),
    ("Imou", ("imou",)),
    ("Hikvision", ("hikvision",)),
    ("Dahua", ("dahua",)),
    ("XMEye/Xiongmai", ("xiongmai", "xmeye", "hangzhou xiongmai")),
    ("Reolink", ("reolink",)),
    ("Foscam", ("foscam", "shenzhen foscam")),
]


def find_advisory(*texts: str) -> tuple[str, dict[str, Any]] | None:
    """Return (vendor, advisory) for the first keyword found in *texts*."""
    haystack = " ".join(t for t in texts if t).lower()
    for name, keywords in _ADVISORY_KEYWORDS:
        if any(k in haystack for k in keywords):
            return name, VENDOR_ADVISORIES[name]
    return None


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


def generate_recommendations(
    device: dict[str, Any], local_prefix: str = "192.168.2"
) -> list[dict[str, Any]]:
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

    vulns = device.get("vulns") or {}
    # The firmware family catches XMEye cameras that call themselves "H264".
    found = find_advisory(vendor, device.get("onvif_manufacturer", ""), vulns.get("family") or "")
    if found:
        vendor, advisory = found
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

    # ── 1b. Firmware vulnerability check (vuln.py) ──────────────────

    # Already on the local-only subnet: the advice stands, the button doesn't.
    isolated = bool(ip) and ip.startswith(f"{local_prefix}.")
    contain = {"action": "info", "action_data": {}} if isolated else {
        "action": "local_only", "action_data": {"mac": mac, "category": "camera"}}
    hits = [f for f in vulns.get("findings", []) if f["status"] in ("affected", "likely")]
    if hits:
        likely = all(f["status"] == "likely" for f in hits)
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": ("Firmware probably has an actively exploited bug: " if likely
                      else "Firmware has an actively exploited bug: ") + ", ".join(f["cve"] for f in hits),
            "detail": "\n".join(f"{f['cve']}: {f['detail']} ({f['source']})" for f in hits)
                      + "\n\nUpdate the firmware from the maker's site if you can, and keep it on local-only "
                        "either way so it can't be reached from the internet.",
            **contain,
        })
    checks = [f for f in vulns.get("findings", []) if f["status"] == "check"]
    if checks and not hits:
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": f"{vulns.get('family')} cameras have actively exploited bugs; couldn't check this one",
            "detail": "\n".join(f"{f['cve']}: {f['detail']}" for f in checks),
            **contain,
        })
    age = vulns.get("firmware_age_years")
    if age is not None and age >= 5:
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": f"Firmware is {age} years old",
            "detail": f"This camera's firmware was built {vulns.get('firmware_date')}. Cheap cameras rarely get "
                      "updates, so anything found since then is still in it. Keep it on local-only.",
            **contain,
        })

    # ── 1c. What UniFi itself saw (security log, traffic history) ───

    sec = device.get("security_events_24h") or 0
    if sec:
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": f"UniFi blocked this device {sec} time{'s' if sec != 1 else ''} in the last 24 hours",
            "detail": "Your own firewall or content-filtering rules stopped it, which UniFi logged as a security "
                      "event. Check the Threats page for what it was trying to reach.",
            "action": "review",
            "action_data": {"mac": mac},
        })
    spike = device.get("traffic_spike")
    if spike:
        mb = spike["last_hour_bytes"] // 1_000_000
        usual = f"; it usually moves about {spike['usual_bytes'] // 1_000_000} MB an hour" if spike.get("usual_bytes") else ""
        recs.append({
            "priority": PRIORITY_HIGH if is_camera else PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH if is_camera else PRIORITY_MEDIUM],
            "title": f"Traffic spike: {mb} MB in the last hour",
            "detail": f"This device moved {mb} MB in the last full hour{usual}."
                      + (" A camera suddenly sending a lot can mean it's uploading video somewhere."
                         if is_camera else ""),
            "action": "review",
            "action_data": {"mac": mac},
        })

    # ── 1d. Phone-home monitor (traffic flows) ──────────────────────

    ph = device.get("phone_home") or {}
    if device.get("containment") == "leaking":
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": f"Not contained: UniFi let {ph.get('allowed', 0)} connection{'s' if ph.get('allowed') != 1 else ''} through",
            "detail": "This device is meant to be cut off from the internet, but UniFi logged traffic it allowed: "
                      + ", ".join(f"{d['host']}:{d['port']}" for d in ph.get("top_destinations", [])[:4])
                      + ". Check that its local-only rule is enabled and above any allow rules, or quarantine it.",
            "action": "quarantine",
            "action_data": {"mac": mac},
        })
    sweep = ph.get("port_sweep")
    if sweep:
        held = device.get("containment") in ("holding", "quiet")
        recs.append({
            "priority": PRIORITY_MEDIUM if held else PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM if held else PRIORITY_HIGH],
            "title": f"Probing for a way out: {sweep['ports']} ports on one server",
            "detail": f"It tried {sweep['ports']} different ports on {sweep['host']}"
                      + (f" ({next(iter(ph.get('regions') or {}), '')})" if ph.get("regions") else "")
                      + ". P2P cameras do this to find any port a firewall forgets to block. "
                      + ("Local-only is stopping all of them." if held else "Put it on local-only so none get through."),
            "action": "info" if held else "local_only",
            "action_data": {} if held else {"mac": mac, "category": "camera"},
        })
    if ph.get("dns_bypass"):
        names = ", ".join(ph["dns_bypass"])
        recs.append({
            "priority": PRIORITY_MEDIUM,
            "priority_label": PRIORITY_LABELS[PRIORITY_MEDIUM],
            "title": f"Uses its own DNS ({names})",
            "detail": "It sends DNS straight to " + names + " instead of the resolver your network hands out, so any "
                      "DNS filtering you run doesn't apply to it. Hard-coded DNS is common on cheap cameras and IoT. "
                      + ("Local-only already blocks it." if device.get("containment") in ("holding", "quiet")
                         else "Local-only would block it, or add a traffic rule that blocks DNS for this device."),
            "action": "info" if device.get("containment") else "local_only",
            "action_data": {} if device.get("containment") else {"mac": mac},
        })

    # ── 1e. Home automation that depends on a cloud ──────────────────

    ha = device.get("home_automation") or {}
    if ha.get("tier") == "cloud_local" and not device.get("containment"):
        recs.append({
            "priority": PRIORITY_LOW,
            "priority_label": PRIORITY_LABELS[PRIORITY_LOW],
            "title": f"{ha['brand']}: talks to its cloud, but can run locally",
            "detail": (ha.get("local_option") or "It has a local control option.")
                      + " Once Home Assistant controls it locally, it can go on local-only without breaking."
                      " Do that in that order: cutting it off first stops it working.",
            "action": "info",
            "action_data": {"mac": mac},
        })

    # ── 2. Camera on main network ────────────────────────────────────

    if is_camera and ip and not ip.startswith(f"{local_prefix}."):
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Camera on main network — not isolated",
            "detail": "This camera is on your main network and can reach other devices and the internet. "
                      f"Move it to the local-only subnet ({local_prefix}.x) to block internet access while "
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
            "detail": "Port 9530 is Dahua's debug service, which older firmware leaves open and which can be used "
                      "to turn on a root shell. Attackers who reach it can view feeds, pull credentials and run "
                      "commands. Quarantine the device until its firmware is updated.",
            "action": "quarantine",
            "action_data": {"mac": mac},
        })

    if 34567 in open_ports or 34568 in open_ports:
        recs.append({
            "priority": PRIORITY_CRITICAL,
            "priority_label": PRIORITY_LABELS[PRIORITY_CRITICAL],
            "title": "XMEye/Xiongmai DVR protocol open",
            "detail": "Ports 34567/34568 are the XMEye/Xiongmai DVR protocol, so this is almost certainly "
                      "an XMEye-based camera or DVR. These normally keep a connection open to Xiongmai's "
                      "cloud, and CVE-2018-10088 allows unauthenticated remote access. The cloud can push "
                      "firmware updates without your consent. Move to local-only subnet or quarantine.",
            "action": "local_only",
            "action_data": {"mac": mac, "category": "camera"},
        })

    p2p_ports = [p for p in [6789, 32100, 19000, 8800] if p in open_ports]
    # These are ordinary ports on plenty of other things, so one of them on
    # its own only counts on something we already think is a camera.
    if p2p_ports and (is_camera or len(p2p_ports) >= 2):
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "P2P cloud relay port open",
            "detail": f"Port(s) {', '.join(map(str, p2p_ports))} are used by camera P2P cloud services, which keep a "
                      "connection to the manufacturer's servers so its app can reach the camera from anywhere. "
                      "That also means your video can pass through servers you don't control. "
                      "Move it to local-only so it can't reach the internet.",
            "action": "local_only",
            "action_data": {"mac": mac, "category": "camera"},
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
    local_prefix: str = "192.168.2",
    hotspots: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Generate network-wide security recommendations."""
    recs: list[dict[str, Any]] = []

    for h in [h for h in hotspots or [] if h["reason"] == "own_camera"]:
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": f"{h['camera_name'] or h['camera_mac']} is running its own Wi-Fi network",
            "detail": f"It's broadcasting “{h['essid'] or '(hidden)'}” on channel {h.get('channel')}. Anyone in range can "
                      "join that network and reach the camera directly, around your firewall and local-only rules. "
                      "Turn off its access-point / hotspot mode in the camera's settings.",
            "action": "info",
            "action_data": {"mac": h["camera_mac"]},
        })
    cloud_only = [d for d in devices if (d.get("home_automation") or {}).get("tier") == "cloud"]
    if cloud_only:
        brands = sorted({d["home_automation"]["brand"] for d in cloud_only})
        recs.append({
            "priority": PRIORITY_INFO,
            "priority_label": PRIORITY_LABELS[PRIORITY_INFO],
            "title": f"{len(cloud_only)} home device{'s' if len(cloud_only) != 1 else ''} only work through a cloud",
            "detail": ", ".join(brands) + ". These stop working if cut off from the internet, so local-only isn't an "
                      "option for them. If that's a concern, look for a local alternative.",
            "action": "info",
            "action_data": {},
        })
    nearby = [h for h in hotspots or [] if h["reason"] == "camera_ssid"]
    if nearby:
        recs.append({
            "priority": PRIORITY_LOW,
            "priority_label": PRIORITY_LABELS[PRIORITY_LOW],
            "title": f"{len(nearby)} camera setup network{'s' if len(nearby) != 1 else ''} in range",
            "detail": "Wi-Fi names like " + ", ".join(f"“{h['essid']}”" for h in nearby[:5]) + " are what cheap "
                      "cameras broadcast until they're set up, or when their hotspot mode is left on. If one is "
                      "yours, finish its setup or turn the hotspot off. It may also be a neighbour's.",
            "action": "info",
            "action_data": {},
        })

    cameras = [d for d in devices if d.get("is_camera")]
    cameras_on_main = [d for d in cameras if not d.get("ip", "").startswith(f"{local_prefix}.")]
    new_count = sum(1 for d in devices if d.get("state") == "new")
    telnet_devices = [d for d in devices if 23 in (d.get("scan_result", {}).get("open_ports", []))]

    if not firewall_exists:
        recs.append({
            "priority": PRIORITY_HIGH,
            "priority_label": PRIORITY_LABELS[PRIORITY_HIGH],
            "title": "Local-only devices missing their internet block",
            "detail": "Some devices assigned to Local Only don't have their traffic rule on the UCG Max yet, "
                      "so they can still reach the internet. Go to the Local Only view and click "
                      "'Create Missing Rules'.",
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
                      f"Move them to the local-only subnet ({local_prefix}.x).",
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
