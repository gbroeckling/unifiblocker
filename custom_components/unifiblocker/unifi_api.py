"""Async API client for UniFi OS controllers (UCG Max, UDM, etc.)."""
from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any

import aiohttp

from .const import (
    API_ALL_USERS,
    API_CLIENTS,
    API_DEVICE_CMD,
    API_DEVICES,
    API_EVENTS,
    API_DPI,
    API_FIREWALL_RULE,
    API_FIREWALL_RULES,
    API_HEALTH,
    API_LOGIN,
    API_NETWORKS,
    API_ROGUE_AP,
    API_USER,
    API_SYSINFO,
)

_LOGGER = logging.getLogger(__name__)

# Timeout for individual HTTP requests (seconds).
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)


class UniFiApiError(Exception):
    """Base exception for UniFi API errors."""


class UniFiAuthError(UniFiApiError):
    """Authentication failed."""


class UniFiConnectionError(UniFiApiError):
    """Could not reach the controller."""


class UniFiApi:
    """Communicate with a UniFi OS controller over its local HTTPS API."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        site: str = "default",
        verify_ssl: bool = False,
        session: aiohttp.ClientSession | None = None,
    ) -> None:
        self._host = host.rstrip("/")
        self._username = username
        self._password = password
        self._site = site
        self._verify_ssl = verify_ssl
        self._session = session
        self._owns_session = session is None
        self._csrf_token: str | None = None

    # ── helpers ──────────────────────────────────────────────────────

    @property
    def _base(self) -> str:
        """Normalize the host into a base URL.

        Accepts any of these input formats:
          192.168.1.1
          192.168.1.1:443
          https://192.168.1.1
          https://192.168.1.1:443
          http://192.168.1.1:8080
          unifi.local

        Defaults to https:// if no scheme is provided (UCG Max always
        uses HTTPS on port 443).
        """
        host = self._host.strip().rstrip("/")
        if "://" in host:
            proto, host = host.split("://", 1)
        else:
            proto = "https"
        # Strip any trailing path segments (e.g. /manage or /network)
        if "/" in host:
            host = host.split("/")[0]
        return f"{proto}://{host}"

    def _url(self, path: str) -> str:
        return self._base + path.format(site=self._site)

    def _ssl_context(self) -> ssl.SSLContext | bool:
        if self._verify_ssl:
            return True
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(
                cookie_jar=jar,
                timeout=REQUEST_TIMEOUT,
            )
            self._owns_session = True
        return self._session

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self._csrf_token:
            headers["x-csrf-token"] = self._csrf_token
        return headers

    # ── public API ───────────────────────────────────────────────────

    async def login(self) -> None:
        """Authenticate and store session cookies + CSRF token."""
        session = await self._ensure_session()
        payload = {"username": self._username, "password": self._password}
        try:
            async with session.post(
                self._url(API_LOGIN),
                json=payload,
                ssl=self._ssl_context(),
            ) as resp:
                if resp.status == 401 or resp.status == 403:
                    raise UniFiAuthError(
                        f"Login failed (HTTP {resp.status}) – check credentials"
                    )
                if resp.status != 200:
                    text = await resp.text()
                    raise UniFiApiError(
                        f"Unexpected login response {resp.status}: {text[:200]}"
                    )
                # UniFi OS returns CSRF token in a response header.
                self._csrf_token = resp.headers.get("x-csrf-token")
        except aiohttp.ClientError as err:
            raise UniFiConnectionError(
                f"Cannot reach {self._base}: {err}"
            ) from err

    async def _request(
        self, method: str, path: str, json: dict | None = None
    ) -> Any:
        """Make an authenticated request; re-login once on 401."""
        session = await self._ensure_session()
        url = self._url(path)

        for attempt in range(2):
            try:
                async with session.request(
                    method,
                    url,
                    json=json,
                    headers=self._headers(),
                    ssl=self._ssl_context(),
                ) as resp:
                    if resp.status == 401 and attempt == 0:
                        _LOGGER.debug("Session expired, re-authenticating")
                        await self.login()
                        continue
                    if resp.status == 401:
                        raise UniFiAuthError("Re-authentication failed")
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
                    # UniFi wraps most responses in {"meta":{}, "data":[]}
                    if isinstance(data, dict) and "data" in data:
                        return data["data"]
                    return data
            except aiohttp.ClientError as err:
                raise UniFiConnectionError(str(err)) from err

        # Should not reach here, but satisfy the type checker.
        raise UniFiApiError("Request failed after retry")

    # ── high-level calls ─────────────────────────────────────────────

    async def get_clients(self) -> list[dict[str, Any]]:
        """Return currently-connected clients."""
        return await self._request("GET", API_CLIENTS)

    async def get_all_users(self) -> list[dict[str, Any]]:
        """Return every known client (online + historical)."""
        return await self._request("GET", API_ALL_USERS)

    async def get_devices(self) -> list[dict[str, Any]]:
        """Return UniFi network devices (APs, switches, gateways)."""
        return await self._request("GET", API_DEVICES)

    async def get_sysinfo(self) -> list[dict[str, Any]]:
        """Return controller system information."""
        return await self._request("GET", API_SYSINFO)

    async def block_client(self, mac: str) -> None:
        """Block a client by MAC address."""
        _LOGGER.info("Blocking client %s", mac)
        await self._request(
            "POST",
            API_DEVICE_CMD,
            json={"cmd": "block-sta", "mac": mac.lower()},
        )

    async def unblock_client(self, mac: str) -> None:
        """Unblock a previously blocked client."""
        _LOGGER.info("Unblocking client %s", mac)
        await self._request(
            "POST",
            API_DEVICE_CMD,
            json={"cmd": "unblock-sta", "mac": mac.lower()},
        )

    async def reconnect_client(self, mac: str) -> None:
        """Force-reconnect (kick) a client."""
        _LOGGER.info("Reconnecting client %s", mac)
        await self._request(
            "POST",
            API_DEVICE_CMD,
            json={"cmd": "kick-sta", "mac": mac.lower()},
        )

    async def get_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent IDS/IPS and connectivity events.

        The UCG Max logs threat events (IPS alerts, rogue DHCP, etc.)
        in its event stream.  We pull the latest *limit* entries.
        """
        return await self._request(
            "GET", API_EVENTS + f"?_limit={limit}"
        )

    async def get_rogue_aps(self) -> list[dict[str, Any]]:
        """Return detected rogue / neighbouring access points."""
        return await self._request("GET", API_ROGUE_AP)

    async def get_health(self) -> list[dict[str, Any]]:
        """Return network health subsystem statuses (WAN, LAN, WLAN)."""
        return await self._request("GET", API_HEALTH)

    async def get_dpi_stats(self) -> list[dict[str, Any]]:
        """Return per-client DPI (Deep Packet Inspection) data.

        Each entry has ``mac``, ``by_cat`` (traffic by category), and
        ``by_app`` (traffic by application).  The UCG Max groups traffic
        into categories like "Streaming", "Web", "Social", etc.
        """
        return await self._request("GET", API_DPI)

    async def test_connection(self) -> dict[str, Any]:
        """Login and fetch sysinfo to verify the connection works.

        Returns the first sysinfo dict on success.
        """
        await self.login()
        info = await self.get_sysinfo()
        return info[0] if info else {}

    async def check_health(self) -> dict[str, Any]:
        """Quick connectivity + health check.

        Returns a summary dict with connection_ok, subsystem statuses,
        and controller hostname.  Used by the connection health sensor.
        """
        result: dict[str, Any] = {"connection_ok": False}
        try:
            info = await self.get_sysinfo()
            result["connection_ok"] = True
            if info:
                result["hostname"] = info[0].get("hostname", "")
                result["version"] = info[0].get("version", "")
                result["uptime"] = info[0].get("uptime", 0)
        except UniFiApiError as err:
            result["error"] = str(err)
            return result

        try:
            health = await self.get_health()
            subsystems = {}
            for sub in health:
                name = sub.get("subsystem", "unknown")
                subsystems[name] = {
                    "status": sub.get("status", "unknown"),
                    "num_adopted": sub.get("num_adopted"),
                    "num_user": sub.get("num_user"),
                    "tx_bytes_r": sub.get("tx_bytes-r"),
                    "rx_bytes_r": sub.get("rx_bytes-r"),
                }
            result["subsystems"] = subsystems
        except UniFiApiError:
            _LOGGER.debug("Health endpoint unavailable", exc_info=True)

        return result

    # ── DHCP reservations ───────────────────────────────────────────

    async def set_fixed_ip(self, user_id: str, ip: str) -> None:
        """Create or update a DHCP reservation for a client.

        *user_id* is the UniFi ``_id`` of the user/client record
        (found in the output of ``get_all_users()``).
        """
        _LOGGER.info("Setting fixed IP %s for user %s", ip, user_id)
        path = API_USER.replace("{user_id}", user_id)
        await self._request(
            "PUT",
            path,
            json={"use_fixedip": True, "fixed_ip": ip},
        )

    async def clear_fixed_ip(self, user_id: str) -> None:
        """Remove a DHCP reservation."""
        _LOGGER.info("Clearing fixed IP for user %s", user_id)
        path = API_USER.replace("{user_id}", user_id)
        await self._request(
            "PUT",
            path,
            json={"use_fixedip": False, "fixed_ip": ""},
        )

    async def get_user_by_mac(self, mac: str) -> dict[str, Any] | None:
        """Find the UniFi user record for a MAC address."""
        users = await self.get_all_users()
        mac = mac.lower()
        for user in users:
            if user.get("mac", "").lower() == mac:
                return user
        return None

    # ── Firewall rules ───────────────────────────────────────────────

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        """Return all firewall rules."""
        return await self._request("GET", API_FIREWALL_RULES)

    async def create_firewall_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        """Create a new firewall rule.

        *rule* should contain at least: name, action, ruleset,
        src_address, dst_address, protocol, etc.
        """
        _LOGGER.info("Creating firewall rule: %s", rule.get("name", "unnamed"))
        result = await self._request("POST", API_FIREWALL_RULES, json=rule)
        return result[0] if isinstance(result, list) and result else result

    async def update_firewall_rule(self, rule_id: str, rule: dict[str, Any]) -> None:
        """Update an existing firewall rule."""
        path = API_FIREWALL_RULE.replace("{rule_id}", rule_id)
        await self._request("PUT", path, json=rule)

    async def delete_firewall_rule(self, rule_id: str) -> None:
        """Delete a firewall rule."""
        path = API_FIREWALL_RULE.replace("{rule_id}", rule_id)
        await self._request("DELETE", path)

    async def block_port_for_mac(
        self, mac: str, port: int, *, protocol: str = "tcp", name: str = ""
    ) -> dict[str, Any]:
        """Create a firewall rule blocking a specific port for one MAC.

        This is a surgical block — the device stays on the network but
        cannot use that port outbound.
        """
        rule_name = name or f"UB: Block {mac} port {port}/{protocol}"
        _LOGGER.info("Creating port block: %s → %d/%s", mac, port, protocol)
        rule = {
            "name": rule_name,
            "enabled": True,
            "action": "drop",
            "ruleset": "LAN_OUT",
            "rule_index": 20100,
            "protocol": protocol,
            "src_firewallgroup_ids": [],
            "src_address": "",
            "src_mac_address": mac.lower(),
            "src_networkconf_id": "",
            "src_networkconf_type": "",
            "dst_firewallgroup_ids": [],
            "dst_address": "",
            "dst_networkconf_id": "",
            "dst_networkconf_type": "",
            "dst_port": str(port),
            "logging": True,
            "state_established": False,
            "state_invalid": False,
            "state_new": True,
            "state_related": False,
        }
        return await self.create_firewall_rule(rule)

    async def block_ports_for_mac(
        self, mac: str, ports: list[int], *, protocol: str = "tcp", name: str = ""
    ) -> dict[str, Any]:
        """Block multiple ports for one MAC in a single rule.

        UniFi accepts comma-separated port lists in dst_port.
        """
        port_str = ",".join(str(p) for p in ports)
        rule_name = name or f"UB: Block {mac} ports {port_str}/{protocol}"
        _LOGGER.info("Creating multi-port block: %s → %s/%s", mac, port_str, protocol)
        rule = {
            "name": rule_name,
            "enabled": True,
            "action": "drop",
            "ruleset": "LAN_OUT",
            "rule_index": 20100,
            "protocol": protocol,
            "src_firewallgroup_ids": [],
            "src_address": "",
            "src_mac_address": mac.lower(),
            "src_networkconf_id": "",
            "src_networkconf_type": "",
            "dst_firewallgroup_ids": [],
            "dst_address": "",
            "dst_networkconf_id": "",
            "dst_networkconf_type": "",
            "dst_port": port_str,
            "logging": True,
            "state_established": False,
            "state_invalid": False,
            "state_new": True,
            "state_related": False,
        }
        return await self.create_firewall_rule(rule)

    async def get_networks(self) -> list[dict[str, Any]]:
        """Return all network configurations."""
        return await self._request("GET", API_NETWORKS)

    async def close(self) -> None:
        """Close the HTTP session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()
            # Give the SSL transport a moment to shut down cleanly.
            await asyncio.sleep(0.25)
