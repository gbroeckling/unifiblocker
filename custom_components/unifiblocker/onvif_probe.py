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


class OnvifProbe:
    """Discover and probe ONVIF cameras on the network."""

    def __init__(self) -> None:
        # ip → probe result
        self._cache: dict[str, dict[str, Any]] = {}
        self._discovered: list[dict[str, Any]] = []

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
            # Create UDP socket for multicast.
            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
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

            sock.close()
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
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
        }
        timeout = aiohttp.ClientTimeout(total=5)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    url, data=body, headers=headers, ssl=ctx
                ) as resp:
                    if resp.status == 200:
                        return await resp.text()
                    # Some cameras return 401 for unauthenticated GetDeviceInformation
                    # but still give useful data in the error response.
                    if resp.status == 401:
                        text = await resp.text()
                        if "Manufacturer" in text or "Model" in text:
                            return text
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
            # Merge discovery info.
            result.update({k: v for k, v in dev.items() if k not in result})
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
