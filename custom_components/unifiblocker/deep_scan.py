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


async def deep_scan_device(
    ip: str, mac: str,
    vendor: str = "", hostname: str = "",
    is_wired: bool = False, open_ports: list[int] | None = None,
) -> dict[str, Any]:
    """Run all fingerprinting techniques on a single device.

    Also uses vendor/hostname from UniFi for additional context.
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
        _probe_mdns(ip),
        return_exceptions=True,
    )

    labels = ["http_80", "http_8080", "https_443", "https_8443",
              "ssh", "dns_reverse", "ttl", "netbios", "mdns"]

    for label, probe in zip(labels, probes):
        if isinstance(probe, Exception):
            continue
        if probe:
            result["techniques"][label] = probe

    # Include UniFi data as a technique so the analyzer can use it.
    if vendor or hostname:
        result["techniques"]["unifi"] = {
            "vendor": vendor,
            "hostname": hostname,
            "is_wired": is_wired,
        }

    # Include port scan data if available.
    if open_ports:
        result["techniques"]["ports"] = {"open_ports": open_ports}

    _LOGGER.info(
        "Deep scan %s: %d techniques returned data (of 8 probed)",
        ip, len(result["techniques"]),
    )

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
        result["best_description"] = "No identifying information found from any technique."
        result["best_confidence"] = "low"

    # Build notes from all findings — everything useful the scan found.
    notes = []
    for tech, data in result["techniques"].items():
        if tech == "unifi":
            continue  # Already known
        for field in ["title", "server", "www_authenticate", "banner", "hostname", "primary"]:
            val = data.get(field, "")
            if val:
                notes.append(f"{tech}.{field}: {val}")
        cert = data.get("cert", {})
        if cert.get("cn"):
            notes.append(f"{tech}.cert_cn: {cert['cn']}")
        if cert.get("org"):
            notes.append(f"{tech}.cert_org: {cert['org']}")
        if data.get("ttl"):
            notes.append(f"ttl: {data['ttl']} ({data.get('os_guess', '?')})")
        names = data.get("names", [])
        if names:
            notes.append(f"netbios: {', '.join(names)}")
        services = data.get("services", [])
        for svc in services:
            notes.append(f"mdns: {svc.get('service','')} → {svc.get('description','')}")
            txt = svc.get("txt", {})
            for k, v in list(txt.items())[:5]:
                notes.append(f"  mdns.{k}: {v}")
    result["notes"] = notes

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


# ── mDNS Service Discovery ───────────────────────────────────────────

# mDNS service types and what they indicate.
_MDNS_SERVICE_MAP: dict[str, tuple[str, str]] = {
    "_airplay._tcp": ("streaming", "AirPlay device (Apple TV, HomePod, speaker)"),
    "_raop._tcp": ("streaming", "AirPlay audio (Apple/compatible speaker)"),
    "_googlecast._tcp": ("smart_speaker", "Google Cast (Chromecast, Nest, Google Home)"),
    "_spotify-connect._tcp": ("smart_speaker", "Spotify Connect device"),
    "_ipp._tcp": ("printer", "IPP printer"),
    "_printer._tcp": ("printer", "Network printer"),
    "_pdl-datastream._tcp": ("printer", "Printer (raw data stream)"),
    "_scanner._tcp": ("printer", "Network scanner"),
    "_hue._tcp": ("led", "Philips Hue bridge"),
    "_homekit._tcp": ("iot", "HomeKit accessory"),
    "_companion-link._tcp": ("phone", "Apple device (iPhone/iPad/Mac)"),
    "_sleep-proxy._udp": ("streaming", "Apple TV (sleep proxy)"),
    "_esphomelib._tcp": ("esphome", "ESPHome device"),
    "_http._tcp": ("iot", "Device with web interface"),
    "_smb._tcp": ("nas", "SMB file share (NAS or computer)"),
    "_afpovertcp._tcp": ("nas", "AFP file share (Mac/NAS)"),
    "_nfs._tcp": ("nas", "NFS file share"),
    "_sonos._tcp": ("smart_speaker", "Sonos speaker"),
    "_daap._tcp": ("streaming", "iTunes/DAAP music server"),
    "_roku._tcp": ("streaming", "Roku device"),
    "_mqtt._tcp": ("iot", "MQTT broker"),
}


async def _probe_mdns(ip: str) -> dict[str, Any] | None:
    """Discover mDNS services advertised by this IP."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser, IPVersion
        import ipaddress

        found_services: list[dict[str, str]] = []

        class Listener:
            def add_service(self, zc, stype, name):
                try:
                    info = zc.get_service_info(stype, name, timeout=2000)
                    if info and info.parsed_addresses():
                        for addr in info.parsed_addresses():
                            if addr == ip:
                                txt = {}
                                if info.properties:
                                    txt = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore")
                                           for k, v in info.properties.items() if isinstance(k, bytes)}
                                cat_info = _MDNS_SERVICE_MAP.get(stype, ("unknown", stype))
                                found_services.append({
                                    "service": stype,
                                    "name": name,
                                    "category": cat_info[0],
                                    "description": cat_info[1],
                                    "txt": txt,
                                })
                except Exception:
                    pass
            def remove_service(self, zc, stype, name): pass
            def update_service(self, zc, stype, name): pass

        zc = Zeroconf(ip_version=IPVersion.V4Only)
        listener = Listener()

        # Browse the most identifying service types.
        browsers = []
        for stype in _MDNS_SERVICE_MAP:
            try:
                browsers.append(ServiceBrowser(zc, f"{stype}.local.", listener))
            except Exception:
                pass

        # Wait for responses.
        await asyncio.sleep(3)

        for b in browsers:
            b.cancel()
        zc.close()

        if found_services:
            # Pick the most specific category.
            best = found_services[0]
            for s in found_services:
                if s["category"] != "iot" and s["category"] != "unknown":
                    best = s
                    break
            return {
                "services": found_services,
                "best_category": best["category"],
                "best_description": best["description"],
                "service_count": len(found_services),
            }
    except ImportError:
        _LOGGER.debug("zeroconf not available for mDNS probe")
    except Exception as err:
        _LOGGER.debug("mDNS probe failed: %s", err)
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

    # mDNS service analysis — highest yield for consumer devices.
    mdns_data = techniques.get("mdns", {})
    if mdns_data:
        mdns_cat = mdns_data.get("best_category", "unknown")
        mdns_desc = mdns_data.get("best_description", "")
        if mdns_cat != "unknown":
            services = mdns_data.get("services", [])
            svc_names = [s.get("service", "") for s in services]
            guesses.append({
                "category": mdns_cat,
                "description": f"{mdns_desc} (mDNS: {', '.join(svc_names[:3])})",
                "confidence": "high",
                "keyword": "mdns",
                "sources": ["mdns"],
            })

    # SSH banner analysis.
    ssh_data = techniques.get("ssh", {})
    banner = ssh_data.get("banner", "")
    if "dropbear" in banner.lower():
        guesses.append({"category": "iot", "description": "Embedded Linux device (dropbear SSH)",
                        "confidence": "medium", "keyword": "dropbear", "sources": ["ssh"]})

    # UniFi vendor/hostname analysis (if no better guess found yet).
    unifi = techniques.get("unifi", {})
    uf_vendor = (unifi.get("vendor") or "").lower()
    uf_hostname = (unifi.get("hostname") or "").lower()
    uf_wired = unifi.get("is_wired", False)

    if uf_vendor or uf_hostname:
        combined = f"{uf_vendor} {uf_hostname}"
        for keywords, category, description in _VENDOR_HOSTNAME_MAP:
            for kw in keywords:
                if kw in combined:
                    guesses.append({
                        "category": category,
                        "description": f"{description} (from UniFi: vendor='{uf_vendor}', hostname='{uf_hostname}')",
                        "confidence": "medium",
                        "keyword": kw,
                        "sources": ["unifi"],
                    })
                    break
            else:
                continue
            break

    # Port-based classification from existing port scan.
    ports_data = techniques.get("ports", {})
    op = ports_data.get("open_ports", [])
    if 554 in op or 8554 in op:
        guesses.append({"category": "camera", "description": "RTSP port open — likely camera",
                        "confidence": "high", "keyword": "rtsp", "sources": ["ports"]})
    if 9100 in op or 631 in op:
        guesses.append({"category": "printer", "description": "Print service port open",
                        "confidence": "high", "keyword": "print", "sources": ["ports"]})
    if 5000 in op or 5001 in op:
        guesses.append({"category": "nas", "description": "Synology/NAS web port open",
                        "confidence": "medium", "keyword": "nas_port", "sources": ["ports"]})
    if 6053 in op:
        guesses.append({"category": "esphome", "description": "ESPHome API port open",
                        "confidence": "high", "keyword": "esphome", "sources": ["ports"]})
    if 8123 in op:
        guesses.append({"category": "ha_device", "description": "Home Assistant port open",
                        "confidence": "high", "keyword": "ha", "sources": ["ports"]})
    if 32400 in op:
        guesses.append({"category": "streaming", "description": "Plex server port open",
                        "confidence": "high", "keyword": "plex", "sources": ["ports"]})

    # If nothing else matched but device is wireless with no ports, likely a phone/tablet.
    if not guesses and not uf_wired and not op:
        if uf_vendor:
            if any(kw in uf_vendor for kw in ["apple", "samsung", "google", "oneplus", "xiaomi", "huawei", "motorola", "oppo", "vivo"]):
                guesses.append({"category": "phone", "description": f"Wireless device from phone vendor ({uf_vendor})",
                                "confidence": "medium", "keyword": "phone_vendor", "sources": ["unifi"]})
            elif any(kw in uf_vendor for kw in ["intel", "realtek", "qualcomm", "mediatek", "broadcom"]):
                guesses.append({"category": "computer", "description": f"Wireless device with PC chipset ({uf_vendor})",
                                "confidence": "low", "keyword": "pc_chip", "sources": ["unifi"]})

    # Sort by confidence.
    conf_order = {"high": 0, "medium": 1, "low": 2}
    guesses.sort(key=lambda g: conf_order.get(g.get("confidence", "low"), 3))

    return guesses


# Extended vendor/hostname keyword map for UniFi data.
_VENDOR_HOSTNAME_MAP: list[tuple[list[str], str, str]] = [
    (["iphone", "ipad", "macbook", "imac", "mac-pro", "apple"], "phone", "Apple device"),
    (["galaxy", "samsung"], "phone", "Samsung device"),
    (["pixel", "nexus", "chromecast", "google home", "google nest"], "smart_speaker", "Google device"),
    (["oneplus"], "phone", "OnePlus phone"),
    (["huawei", "honor"], "phone", "Huawei device"),
    (["xiaomi", "redmi", "poco"], "phone", "Xiaomi device"),
    (["motorola", "moto"], "phone", "Motorola phone"),
    (["oppo", "realme", "vivo"], "phone", "Phone"),
    (["echo", "amazon", "fire-tv", "kindle"], "smart_speaker", "Amazon device"),
    (["roku"], "streaming", "Roku"),
    (["sonos"], "smart_speaker", "Sonos speaker"),
    (["playstation", "ps4", "ps5", "sony"], "gaming", "PlayStation"),
    (["xbox", "microsoft"], "gaming", "Xbox/Microsoft"),
    (["nintendo", "switch"], "gaming", "Nintendo"),
    (["dell", "hp ", "lenovo", "thinkpad", "asus", "acer"], "computer", "Computer"),
    (["synology", "diskstation"], "nas", "Synology NAS"),
    (["qnap"], "nas", "QNAP NAS"),
    (["netgear"], "networking", "Netgear device"),
    (["ubiquiti", "ubnt", "unifi"], "networking", "Ubiquiti device"),
    (["tp-link", "tplink", "tapo", "kasa"], "iot", "TP-Link device"),
    (["hikvision", "dahua", "reolink", "amcrest", "foscam"], "camera", "IP camera"),
    (["espressif", "esp32", "esp8266", "esphome"], "esphome", "ESP device"),
    (["shelly"], "iot", "Shelly device"),
    (["tuya", "smart life"], "iot", "Tuya IoT device"),
    (["ring"], "camera", "Ring camera"),
    (["wyze"], "camera", "Wyze camera"),
    (["ecobee", "nest thermostat"], "iot", "Smart thermostat"),
    (["hue", "philips"], "led", "Philips Hue"),
    (["wled", "govee", "yeelight", "nanoleaf", "lifx"], "led", "Smart light"),
    (["brother", "canon", "epson", "hp laserjet", "hp officejet"], "printer", "Printer"),
    (["tesla"], "iot", "Tesla vehicle"),
    (["lg", "lg electronics"], "streaming", "LG device"),
    (["vmware", "proxmox", "esxi"], "computer", "Virtual machine host"),
    (["raspberry", "raspberrypi"], "computer", "Raspberry Pi"),
]


async def deep_scan_multiple(targets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Deep-scan multiple devices sequentially."""
    results: dict[str, dict[str, Any]] = {}
    for t in targets:
        ip = t.get("ip", "")
        mac = t.get("mac", "")
        if ip and mac:
            try:
                results[mac.lower()] = await deep_scan_device(
                    ip, mac,
                    vendor=t.get("vendor", ""),
                    hostname=t.get("hostname", ""),
                    is_wired=t.get("is_wired", False),
                    open_ports=t.get("open_ports"),
                )
            except Exception as err:
                _LOGGER.debug("Deep scan failed for %s: %s", ip, err)
    return results
