"""Deep device fingerprinting — uses every available technique to identify unknowns.

Techniques (in order of reliability):
1. mDNS service discovery — richest data, reveals device type + model
2. HTTP banner/title grabbing — catches anything with a web UI
3. TLS certificate inspection — manufacturer from cert subject/issuer
4. SSH banner grabbing — OS and device type from SSH version string
5. DNS reverse lookup — hostname often reveals device type
6. TTL analysis — OS family from ping TTL (64=Linux, 128=Windows, 255=network)
7. SSDP/UPnP discovery — device description XML with manufacturer/model
8. NetBIOS name query — Windows/Samba device names

No extra pip dependencies — uses aiohttp (already in HA), ssl stdlib,
asyncio stdlib, and zeroconf (already in HA).
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
import struct
import time
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

PROBE_TIMEOUT = 3  # seconds per technique


async def deep_scan_device(ip: str, mac: str) -> dict[str, Any]:
    """Run all fingerprinting techniques on a single device.

    Returns a dict with findings from each technique and a best-guess
    device identification.
    """
    mac = mac.lower()
    result: dict[str, Any] = {
        "ip": ip, "mac": mac, "scan_time": time.time(),
        "techniques": {},
        "guesses": [],
    }

    # Run all probes concurrently.
    probes = await asyncio.gather(
        _probe_http(ip, 80),
        _probe_http(ip, 8080),
        _probe_https(ip, 443),
        _probe_https(ip, 8443),
        _probe_ssh(ip),
        _probe_dns_reverse(ip),
        _probe_ttl(ip),
        _probe_netbios(ip),
        return_exceptions=True,
    )

    labels = ["http_80", "http_8080", "https_443", "https_8443",
              "ssh", "dns_reverse", "ttl", "netbios"]

    for label, probe in zip(labels, probes):
        if isinstance(probe, Exception):
            continue
        if probe:
            result["techniques"][label] = probe

    # Analyze all findings and produce guesses.
    result["guesses"] = _analyze_findings(result["techniques"])

    # Pick the best guess.
    if result["guesses"]:
        best = result["guesses"][0]
        result["best_guess"] = best.get("category", "unknown")
        result["best_description"] = best.get("description", "")
        result["best_confidence"] = best.get("confidence", "low")
    else:
        result["best_guess"] = "unknown"
        result["best_description"] = "Could not identify device with any technique."
        result["best_confidence"] = "low"

    return result


# ── HTTP Banner / Title ──────────────────────────────────────────────

async def _probe_http(ip: str, port: int) -> dict[str, Any] | None:
    timeout = aiohttp.ClientTimeout(total=PROBE_TIMEOUT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"http://{ip}:{port}/", ssl=False) as resp:
                headers = dict(resp.headers)
                body = await resp.text(errors="ignore")
                body = body[:4000]

                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:200]

                server = headers.get("Server", "")
                www_auth = headers.get("WWW-Authenticate", "")
                x_powered = headers.get("X-Powered-By", "")

                return {
                    "title": title,
                    "server": server,
                    "www_authenticate": www_auth,
                    "x_powered_by": x_powered,
                    "status": resp.status,
                    "port": port,
                }
    except Exception:
        return None


async def _probe_https(ip: str, port: int) -> dict[str, Any] | None:
    """Grab HTTPS banner AND inspect TLS certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    result: dict[str, Any] = {"port": port}

    # TLS certificate inspection.
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx),
            timeout=PROBE_TIMEOUT,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            der = ssl_obj.getpeercert(binary_form=True)
            # Parse certificate subject/issuer from DER.
            cert_info = _parse_cert_quick(der)
            result["cert"] = cert_info

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass

    # Also try HTTP over HTTPS for banner.
    timeout = aiohttp.ClientTimeout(total=PROBE_TIMEOUT)
    try:
        conn = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
            async with session.get(f"https://{ip}:{port}/", ssl=ctx) as resp:
                headers = dict(resp.headers)
                body = await resp.text(errors="ignore")
                body = body[:4000]

                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:200]

                result["title"] = title
                result["server"] = headers.get("Server", "")
                result["www_authenticate"] = headers.get("WWW-Authenticate", "")
    except Exception:
        pass

    return result if len(result) > 1 else None


def _parse_cert_quick(der_bytes: bytes) -> dict[str, str]:
    """Extract basic cert info without the cryptography library."""
    info: dict[str, str] = {}
    # Look for common OID patterns in the DER.
    text = der_bytes.decode("latin-1", errors="ignore")
    # Common Name (OID 2.5.4.3)
    for pattern in [r"CN=([^,/\x00]+)", r"commonName[^\x00]*?([A-Za-z][\w\s\.\-]+)"]:
        m = re.search(pattern, text)
        if m:
            info["cn"] = m.group(1).strip()[:100]
            break
    # Organization (OID 2.5.4.10)
    for pattern in [r"O=([^,/\x00]+)", r"organizationName[^\x00]*?([A-Za-z][\w\s\.\-]+)"]:
        m = re.search(pattern, text)
        if m:
            info["org"] = m.group(1).strip()[:100]
            break
    return info


# ── SSH Banner ───────────────────────────────────────────────────────

async def _probe_ssh(ip: str) -> dict[str, Any] | None:
    for port in [22, 2222]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=PROBE_TIMEOUT,
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=2)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            banner_str = banner.decode("utf-8", errors="ignore").strip()
            if banner_str:
                return {"banner": banner_str, "port": port}
        except Exception:
            continue
    return None


# ── DNS Reverse Lookup ───────────────────────────────────────────────

async def _probe_dns_reverse(ip: str) -> dict[str, Any] | None:
    loop = asyncio.get_event_loop()
    try:
        hostname = await asyncio.wait_for(
            loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0]),
            timeout=PROBE_TIMEOUT,
        )
        if hostname and hostname != ip:
            return {"hostname": hostname}
    except Exception:
        pass
    return None


# ── TTL Analysis ─────────────────────────────────────────────────────

async def _probe_ttl(ip: str) -> dict[str, Any] | None:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "2", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4)
        output = stdout.decode("utf-8", errors="ignore")
        m = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
        if m:
            ttl = int(m.group(1))
            os_guess = "unknown"
            if ttl <= 64:
                os_guess = "linux"
            elif ttl <= 128:
                os_guess = "windows"
            elif ttl <= 255:
                os_guess = "network_equipment"
            return {"ttl": ttl, "os_guess": os_guess}
    except Exception:
        pass
    return None


# ── NetBIOS Name Query ───────────────────────────────────────────────

async def _probe_netbios(ip: str) -> dict[str, Any] | None:
    """Send a NetBIOS name status query (UDP 137)."""
    # NetBIOS status query packet.
    query = (
        b"\x80\x94"  # Transaction ID
        b"\x00\x00"  # Flags
        b"\x00\x01"  # Questions
        b"\x00\x00"  # Answers
        b"\x00\x00"  # Authority
        b"\x00\x00"  # Additional
        b"\x20"      # Name length (32)
        + b"\x43\x4b" * 16  # Encoded "*" (wildcard)
        + b"\x00"    # Null terminator
        + b"\x00\x21"  # Type: NBSTAT
        + b"\x00\x01"  # Class: IN
    )

    loop = asyncio.get_event_loop()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(PROBE_TIMEOUT)
        sock.setblocking(False)

        await loop.sock_sendto(sock, query, (ip, 137))
        data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, 1024),
            timeout=PROBE_TIMEOUT,
        )
        sock.close()

        if len(data) > 56:
            num_names = data[56]
            names = []
            offset = 57
            for _ in range(min(num_names, 10)):
                if offset + 18 > len(data):
                    break
                name = data[offset:offset + 15].decode("ascii", errors="ignore").strip()
                name_type = data[offset + 15]
                if name and name_type == 0x00:
                    names.append(name)
                offset += 18
            if names:
                return {"names": names, "primary": names[0]}
    except Exception:
        pass
    return None


# ── Analyze all findings ─────────────────────────────────────────────

# Maps keywords found in banners/titles/certs to categories.
_KEYWORD_MAP: list[tuple[list[str], str, str]] = [
    # NAS
    (["synology", "diskstation", "dsm"], "nas", "Synology NAS"),
    (["qnap", "qts"], "nas", "QNAP NAS"),
    (["truenas", "freenas"], "nas", "TrueNAS/FreeNAS"),
    (["unraid"], "nas", "Unraid NAS"),
    (["netgear readynas", "readynas"], "nas", "Netgear ReadyNAS"),
    (["western digital", "wd my cloud", "mycloud"], "nas", "WD MyCloud NAS"),
    (["unas", "unifi nas"], "nas", "UniFi NAS"),
    (["openmediavault", "omv"], "nas", "OpenMediaVault NAS"),
    # Cameras
    (["hikvision", "hik-connect", "isapi"], "camera", "Hikvision camera"),
    (["dahua", "dh-", "easy4ip"], "camera", "Dahua camera"),
    (["reolink"], "camera", "Reolink camera"),
    (["amcrest"], "camera", "Amcrest camera"),
    (["foscam"], "camera", "Foscam camera"),
    (["ip camera", "ipcam", "webcam", "network camera"], "camera", "IP camera"),
    (["onvif", "rtsp"], "camera", "ONVIF/RTSP camera"),
    (["axis communications"], "camera", "Axis camera"),
    (["ubnt aircam", "unifi protect", "unifi video"], "camera", "Ubiquiti camera"),
    # Networking
    (["unifi", "ubiquiti", "ubnt"], "networking", "Ubiquiti network device"),
    (["netgear"], "networking", "Netgear device"),
    (["tp-link", "tplink"], "networking", "TP-Link device"),
    (["mikrotik", "routeros", "rosssh"], "networking", "MikroTik router"),
    (["cisco"], "networking", "Cisco device"),
    (["aruba"], "networking", "Aruba device"),
    # Smart home / IoT
    (["hue", "philips hue"], "led", "Philips Hue bridge"),
    (["wled"], "led", "WLED LED controller"),
    (["esphome", "esph-"], "esphome", "ESPHome device"),
    (["home assistant", "hassio"], "ha_device", "Home Assistant"),
    (["tasmota"], "iot", "Tasmota device"),
    (["shelly"], "iot", "Shelly device"),
    (["sonos"], "smart_speaker", "Sonos speaker"),
    (["echo", "alexa"], "smart_speaker", "Amazon Echo"),
    (["google cast", "chromecast", "google home"], "smart_speaker", "Google/Nest device"),
    # Printers
    (["printer", "laserjet", "officejet", "deskjet", "epson", "canon",
      "brother", "cups", "ipp"], "printer", "Network printer"),
    # Computers
    (["windows", "microsoft"], "computer", "Windows PC"),
    (["ubuntu", "debian", "fedora", "centos", "rhel"], "computer", "Linux computer"),
    (["freebsd", "openbsd"], "computer", "BSD system"),
    (["openssh_for_windows"], "computer", "Windows PC (SSH)"),
    # Streaming
    (["plex", "plexmediaserver"], "streaming", "Plex server"),
    (["jellyfin"], "streaming", "Jellyfin server"),
    (["roku"], "streaming", "Roku device"),
    (["samsung tv", "tizen", "samsung smart"], "streaming", "Samsung Smart TV"),
    (["lg webos", "lg smart"], "streaming", "LG Smart TV"),
    (["apple tv", "airplay"], "streaming", "Apple TV"),
    # Gaming
    (["playstation", "ps4", "ps5"], "gaming", "PlayStation"),
    (["xbox"], "gaming", "Xbox"),
    (["nintendo"], "gaming", "Nintendo"),
]


def _analyze_findings(techniques: dict[str, Any]) -> list[dict[str, Any]]:
    """Analyze all probe results and return ranked guesses."""
    guesses: list[dict[str, Any]] = []
    all_text = ""

    # Gather all text from all techniques.
    for tech_name, data in techniques.items():
        for field in ["title", "server", "www_authenticate", "x_powered_by",
                       "banner", "hostname", "primary"]:
            val = data.get(field, "")
            if val:
                all_text += f" {val}"
        cert = data.get("cert", {})
        for field in ["cn", "org"]:
            val = cert.get(field, "")
            if val:
                all_text += f" {val}"
        names = data.get("names", [])
        all_text += " ".join(names)

    all_text_lower = all_text.lower()

    # Check each keyword pattern.
    for keywords, category, description in _KEYWORD_MAP:
        for kw in keywords:
            if kw in all_text_lower:
                # Higher confidence if found in multiple techniques.
                sources = []
                for tech_name, data in techniques.items():
                    tech_text = ""
                    for field in ["title", "server", "www_authenticate",
                                   "banner", "hostname", "primary"]:
                        tech_text += f" {data.get(field, '')}"
                    cert = data.get("cert", {})
                    tech_text += f" {cert.get('cn', '')} {cert.get('org', '')}"
                    if kw in tech_text.lower():
                        sources.append(tech_name)

                confidence = "high" if len(sources) >= 2 else "medium"
                guesses.append({
                    "category": category,
                    "description": f"{description} (found '{kw}' in {', '.join(sources)})",
                    "confidence": confidence,
                    "keyword": kw,
                    "sources": sources,
                })
                break  # Only match first keyword per pattern.

    # TTL-based OS guess (lower confidence).
    ttl_data = techniques.get("ttl", {})
    os_guess = ttl_data.get("os_guess", "")
    if os_guess == "windows":
        guesses.append({"category": "computer", "description": "Windows device (TTL ~128)",
                        "confidence": "low", "keyword": "ttl", "sources": ["ttl"]})
    elif os_guess == "network_equipment":
        guesses.append({"category": "networking", "description": "Network equipment (TTL ~255)",
                        "confidence": "low", "keyword": "ttl", "sources": ["ttl"]})

    # SSH banner analysis.
    ssh_data = techniques.get("ssh", {})
    banner = ssh_data.get("banner", "")
    if "dropbear" in banner.lower():
        guesses.append({"category": "iot", "description": "Embedded Linux device (dropbear SSH)",
                        "confidence": "medium", "keyword": "dropbear", "sources": ["ssh"]})

    # Sort by confidence.
    conf_order = {"high": 0, "medium": 1, "low": 2}
    guesses.sort(key=lambda g: conf_order.get(g.get("confidence", "low"), 3))

    return guesses


async def deep_scan_multiple(targets: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    """Deep-scan multiple devices sequentially."""
    results: dict[str, dict[str, Any]] = {}
    for t in targets:
        ip = t.get("ip", "")
        mac = t.get("mac", "")
        if ip and mac:
            try:
                results[mac.lower()] = await deep_scan_device(ip, mac)
            except Exception as err:
                _LOGGER.debug("Deep scan failed for %s: %s", ip, err)
    return results
