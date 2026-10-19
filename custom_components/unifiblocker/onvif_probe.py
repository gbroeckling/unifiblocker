"""ONVIF discovery and device probe engine.

Uses the ONVIF protocol to DEFINITIVELY identify IP cameras on the
network.  Instead of guessing from MACs, we ask the device directly:
"What are you?"

Two phases:
  1. WS-Discovery — UDP multicast probe on port 3702 finds all
     ONVIF-capable devices and returns their service URLs
  2. GetDeviceInformation — SOAP request to each device returns
     manufacturer, model, firmware version, serial number, hardware ID

This is how ONVIF Device Manager (ODM) works under the hood.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from typing import Any
from xml.etree import ElementTree as ET

import aiohttp
from homeassistant.util.ssl import get_default_no_verify_context

_LOGGER = logging.getLogger(__name__)

# ── WS-Discovery ────────────────────────────────────────────────────

MULTICAST_ADDR = "239.255.255.250"
MULTICAST_PORT = 3702
DISCOVERY_TIMEOUT = 4  # seconds to wait for responses

# WS-Discovery probe message for ONVIF devices.
WS_DISCOVERY_PROBE = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:unifiblocker-probe-{msg_id}</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe>
      <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
    </wsd:Probe>
  </soap:Body>
</soap:Envelope>"""

# ── ONVIF SOAP requests ─────────────────────────────────────────────

DEVICE_INFO_REQUEST = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetDeviceInformation/>
  </soap:Body>
</soap:Envelope>"""

DEVICE_SCOPES_REQUEST = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetScopes/>
  </soap:Body>
</soap:Envelope>"""

DEVICE_CAPABILITIES_REQUEST = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <soap:Body>
    <tds:GetCapabilities>
      <tds:Category>All</tds:Category>
    </tds:GetCapabilities>
  </soap:Body>
</soap:Envelope>"""

# Common ONVIF device service paths.
ONVIF_PATHS = [
    "/onvif/device_service",
    "/onvif/device_service/",
    "/onvif/services",
]

# XML namespaces used in ONVIF responses.
NS = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "wsd": "http://schemas.xmlsoap.org/ws/2005/04/discovery",
    "wsa": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
}


def is_video_device(types: str) -> bool:
    """True if a WS-Discovery Types list says ONVIF video device."""
    return "networkvideotransmitter" in (types or "").lower()


def has_onvif_evidence(r: dict[str, Any]) -> bool:
    """A positive result we can stand behind: the device named itself, asked
    for an ONVIF login, or announced itself as a video transmitter."""
    if not r.get("onvif"):
        return False
    if r.get("source") == "ws-discovery" and not is_video_device(r.get("types", "")):
        return False   # a NAS/PC answering WS-Discovery (saved by 0.3.51-0.3.54)
    return bool(r.get("manufacturer") or r.get("model") or r.get("firmware_version")
                or r.get("auth_required") or is_video_device(r.get("types", "")))


class OnvifProbe:
    """Discover and probe ONVIF cameras on the network."""

    def __init__(self, hass: Any = None) -> None:
        # ip → probe result
        self._cache: dict[str, dict[str, Any]] = {}
        self._discovered: list[dict[str, Any]] = []
        # URLs that answered with an ONVIF/SOAP fault (service there, login needed).
        self._fault_urls: set[str] = set()
        # mac → last positive result (with the IP it was seen on). Saved, so a
        # camera keeps its ONVIF identity across restarts and IP changes.
        self._by_mac: dict[str, dict[str, Any]] = {}
        self._probed: dict[str, dict[str, Any]] = {}   # mac → last probe (any outcome)
        self._store = None
        if hass is not None:
            from homeassistant.helpers.storage import Store
            self._store = Store(hass, 1, "unifiblocker_onvif")

    async def async_load(self) -> None:
        if self._store:
            data = await self._store.async_load()
            if isinstance(data, dict):
                # 0.3.52-0.3.55 could save NAS/PC WS-Discovery replies and
                # web servers that redirect /onvif/... as cameras. Keep only
                # records with real evidence; real cameras get re-found by
                # discovery anyway.
                self._by_mac = {
                    mac: r for mac, r in data.get("by_mac", {}).items() if has_onvif_evidence(r)
                }
                self._probed = data.get("probed", {})

    def _save(self) -> None:
        if self._store:
            self._store.async_delay_save(lambda: {"by_mac": self._by_mac, "probed": self._probed}, 30)

    def note_probe(self, mac: str, ip: str) -> None:
        """Record that *mac* was probed at *ip*, positive or not, so devices
        without ONVIF aren't probed again on every restart."""
        self._probed[mac.lower()] = {"ip": ip, "probe_time": time.time()}
        self.link(mac, ip)
        self._save()

    def link(self, mac: str, ip: str) -> bool:
        """Remember a positive result for *ip* under *mac*. True if it changed."""
        r = self._cache.get(ip)
        mac = mac.lower()
        if not r or not has_onvif_evidence(r):
            return False
        old = self._by_mac.get(mac)
        if old and old.get("probe_time", 0) >= r.get("probe_time", 0) and old.get("ip") == ip:
            return False
        self._by_mac[mac] = {**r, "ip": ip}
        self._save()
        return True

    def result_for(self, mac: str, ip: str) -> dict[str, Any] | None:
        """Best ONVIF result for a client: a positive one for its current IP,
        else what we last knew about its MAC, else whatever the IP gave."""
        live = self._cache.get(ip) if ip else None
        if live and live.get("onvif"):
            return live
        return self._by_mac.get(mac.lower()) or live

    def known_for(self, mac: str) -> dict[str, Any] | None:
        """The newest thing we know for *mac*: a positive result, or just the
        last probe. Both carry "ip" and "probe_time"."""
        mac = mac.lower()
        hits = [r for r in (self._by_mac.get(mac), self._probed.get(mac)) if r]
        return max(hits, key=lambda r: r.get("probe_time", 0)) if hits else None

    @property
    def cache(self) -> dict[str, dict[str, Any]]:
        return self._cache

    @property
    def discovered_devices(self) -> list[dict[str, Any]]:
        return self._discovered

    def get_result(self, ip: str) -> dict[str, Any] | None:
        return self._cache.get(ip)

    def get_result_by_mac(self, mac: str) -> dict[str, Any] | None:
        """Find ONVIF result by MAC (matches against discovered info)."""
        mac = mac.lower().replace("-", ":")
        for result in self._cache.values():
            if result.get("mac", "").lower() == mac:
                return result
        return None

    # ── WS-Discovery ─────────────────────────────────────────────────

    async def discover(self) -> list[dict[str, Any]]:
        """Send WS-Discovery probe and collect responses.

        Returns list of discovered devices with their service URLs.
        """
        msg_id = str(int(time.time() * 1000))
        probe_msg = WS_DISCOVERY_PROBE.replace("{msg_id}", msg_id).encode("utf-8")

        devices: list[dict[str, Any]] = []

        try:
            # Create UDP socket for multicast. The with block closes it on
            # every path, errors included.
            loop = asyncio.get_running_loop()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
                sock.setblocking(False)

                # Send probe.
                await loop.sock_sendto(sock, probe_msg, (MULTICAST_ADDR, MULTICAST_PORT))
                _LOGGER.info("Sent ONVIF WS-Discovery probe")

                # Collect responses.
                end_time = time.time() + DISCOVERY_TIMEOUT
                while time.time() < end_time:
                    try:
                        data, addr = await asyncio.wait_for(
                            loop.sock_recvfrom(sock, 65535),
                            timeout=max(0.1, end_time - time.time()),
                        )
                        device = self._parse_discovery_response(data, addr[0])
                        if device:
                            devices.append(device)
                    except asyncio.TimeoutError:
                        break
                    except Exception:
                        continue
        except Exception as err:
            _LOGGER.warning("WS-Discovery failed: %s", err)

        self._discovered = devices
        _LOGGER.info("ONVIF discovery found %d devices", len(devices))
        return devices

    def _parse_discovery_response(self, data: bytes, sender_ip: str) -> dict[str, Any] | None:
        """Parse a WS-Discovery ProbeMatch response."""
        try:
            root = ET.fromstring(data)
            # Extract XAddrs (service URLs).
            xaddrs = ""
            for elem in root.iter():
                if elem.tag.endswith("XAddrs") and elem.text:
                    xaddrs = elem.text.strip()
                    break

            # Extract scopes.
            scopes = ""
            for elem in root.iter():
                if elem.tag.endswith("Scopes") and elem.text:
                    scopes = elem.text.strip()
                    break

            # Extract types.
            types = ""
            for elem in root.iter():
                if elem.tag.endswith("Types") and elem.text:
                    types = elem.text.strip()
                    break

            # Parse scope for hardware/name info.
            scope_info = self._parse_scopes(scopes)

            # Determine the device service URL.
            service_url = ""
            if xaddrs:
                # Take the first URL (usually HTTP on port 80).
                urls = xaddrs.split()
                service_url = urls[0] if urls else ""

            return {
                "ip": sender_ip,
                "service_url": service_url,
                "xaddrs": xaddrs,
                "types": types,
                "scopes_raw": scopes,
                **scope_info,
            }
        except ET.ParseError:
            return None

    def _parse_scopes(self, scopes: str) -> dict[str, str]:
        """Extract device info from ONVIF scope URIs."""
        info: dict[str, str] = {}
        if not scopes:
            return info

        for scope in scopes.split():
            scope = scope.strip()
            # onvif://www.onvif.org/name/Camera1
            if "/name/" in scope:
                info["scope_name"] = scope.split("/name/")[-1].replace("%20", " ")
            # onvif://www.onvif.org/hardware/DS-2CD2043G2-I
            elif "/hardware/" in scope:
                info["scope_hardware"] = scope.split("/hardware/")[-1].replace("%20", " ")
            # onvif://www.onvif.org/type/video_encoder
            elif "/type/" in scope:
                info.setdefault("scope_types", [])
                info["scope_types"] = scope.split("/type/")[-1]
            # onvif://www.onvif.org/location/...
            elif "/location/" in scope:
                info["scope_location"] = scope.split("/location/")[-1].replace("%20", " ")
            # onvif://www.onvif.org/Profile/...
            elif "/Profile/" in scope:
                profiles = info.get("scope_profiles", "")
                p = scope.split("/Profile/")[-1]
                info["scope_profiles"] = f"{profiles}, {p}" if profiles else p

        return info

    # ── Device Information ───────────────────────────────────────────

    async def probe_device(self, ip: str, port: int = 80) -> dict[str, Any]:
        """Query a device's ONVIF service for detailed information.

        Tries multiple common ONVIF paths and extracts:
        - Manufacturer, Model, FirmwareVersion, SerialNumber, HardwareId
        - Scopes (name, hardware model)
        - Capabilities
        """
        result: dict[str, Any] = {
            "ip": ip,
            "port": port,
            "onvif": True,
            "probe_time": time.time(),
        }

        # Try each common ONVIF path.
        device_info = None
        for path in ONVIF_PATHS:
            url = f"http://{ip}:{port}{path}"
            device_info = await self._soap_request(url, DEVICE_INFO_REQUEST)
            if device_info is not None:
                result["service_url"] = url
                break

        if device_info is None:
            # Try HTTPS.
            for path in ONVIF_PATHS:
                url = f"https://{ip}:{port}{path}"
                device_info = await self._soap_request(url, DEVICE_INFO_REQUEST)
                if device_info is not None:
                    result["service_url"] = url
                    break

        if device_info is None:
            prefix = (f"http://{ip}:{port}/", f"https://{ip}:{port}/")
            fault = next((u for u in self._fault_urls if u.startswith(prefix)), None)
            if fault:
                # It speaks ONVIF but wants a login. That's still a camera.
                self._fault_urls -= {u for u in self._fault_urls if u.startswith(prefix)}
                result.update({"service_url": fault, "auth_required": True})
                self._cache[ip] = result
                return result
            result["onvif"] = False
            result["error"] = "No ONVIF service found"
            self._cache[ip] = result
            return result

        # Parse GetDeviceInformation response.
        info = self._parse_device_info(device_info)
        result.update(info)

        # Try GetScopes for additional details.
        try:
            scopes_resp = await self._soap_request(result["service_url"], DEVICE_SCOPES_REQUEST)
            if scopes_resp:
                scopes_text = ""
                for elem in ET.fromstring(scopes_resp).iter():
                    if elem.tag.endswith("ScopeItem") and elem.text:
                        scopes_text += elem.text.strip() + " "
                scope_info = self._parse_scopes(scopes_text)
                result.update(scope_info)
        except Exception:
            pass

        self._cache[ip] = result
        _LOGGER.info(
            "ONVIF probe %s: %s %s (fw: %s, sn: %s)",
            ip, result.get("manufacturer", "?"), result.get("model", "?"),
            result.get("firmware_version", "?"), result.get("serial_number", "?"),
        )
        return result

    async def _soap_request(self, url: str, body: str) -> str | None:
        """Send a SOAP request and return the response body."""
        # HA's shared no-verify context: built once at startup, so no disk
        # reads on the event loop. Never modify it, other integrations use it.
        ctx = get_default_no_verify_context()

        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
        }
        timeout = aiohttp.ClientTimeout(total=5)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # No redirects: plenty of web servers bounce /onvif/... to a
                # login page, and that 200 HTML isn't an ONVIF answer.
                async with session.post(
                    url, data=body, headers=headers, ssl=ctx, allow_redirects=False
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        return text if "envelope" in text[:4000].lower() else None
                    # Some cameras return 401 for unauthenticated GetDeviceInformation
                    # but still give useful data in the error response.
                    if resp.status in (400, 401, 403, 500):
                        text = await resp.text()
                        if resp.status == 401 and ("Manufacturer" in text or "Model" in text):
                            return text
                        # A SOAP/ONVIF fault ("NotAuthorized" etc.) means an ONVIF
                        # service is there and wants a login. A plain 401 page
                        # doesn't: routers and NAS boxes answer every path that way.
                        low = text[:4000].lower()
                        if "envelope" in low and ("onvif" in low or "notauthorized" in low):
                            self._fault_urls.add(url)
        except Exception:
            pass
        return None

    def _parse_device_info(self, xml_text: str) -> dict[str, Any]:
        """Extract device info from GetDeviceInformation response."""
        info: dict[str, Any] = {}
        try:
            root = ET.fromstring(xml_text)
            # Find the GetDeviceInformationResponse element.
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                if tag == "Manufacturer" and elem.text:
                    info["manufacturer"] = elem.text.strip()
                elif tag == "Model" and elem.text:
                    info["model"] = elem.text.strip()
                elif tag == "FirmwareVersion" and elem.text:
                    info["firmware_version"] = elem.text.strip()
                elif tag == "SerialNumber" and elem.text:
                    info["serial_number"] = elem.text.strip()
                elif tag == "HardwareId" and elem.text:
                    info["hardware_id"] = elem.text.strip()
        except ET.ParseError:
            _LOGGER.debug("Failed to parse ONVIF response", exc_info=True)
        return info

    # ── Batch operations ─────────────────────────────────────────────

    async def discover_and_probe_all(self) -> list[dict[str, Any]]:
        """Run WS-Discovery then probe each discovered device."""
        devices = await self.discover()
        results = []
        for dev in devices:
            ip = dev.get("ip", "")
            if not ip:
                continue
            # Determine port from service URL if available.
            port = 80
            surl = dev.get("service_url", "")
            if surl:
                match = re.search(r":(\d+)", surl.split("//")[-1])
                if match:
                    port = int(match.group(1))
            result = await self.probe_device(ip, port)
            if not result.get("onvif") and is_video_device(dev.get("types", "")):
                # It answered WS-Discovery as a video transmitter, so it is
                # one, even if the follow-up probe got nowhere without a login.
                # (Windows and NAS boxes answer WS-Discovery too, as
                # "wsdp:Device pub:Computer"; those don't count.)
                result.update({"onvif": True, "auth_required": True, "source": "ws-discovery"})
                result.pop("error", None)
            if not result.get("model") and dev.get("scope_hardware"):
                result["model"] = dev["scope_hardware"]
            # Merge discovery info.
            result.update({k: v for k, v in dev.items() if k not in result})
            self._cache[ip] = result
            results.append(result)
        return results

    async def probe_ip(self, ip: str) -> dict[str, Any]:
        """Probe a single IP for ONVIF, trying common ports."""
        for port in [80, 8080, 8899, 2020, 443, 8443]:
            result = await self.probe_device(ip, port)
            if result.get("onvif"):
                return result
        # Return last attempt (will have onvif=False).
        return result
