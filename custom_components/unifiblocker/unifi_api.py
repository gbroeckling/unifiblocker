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
    API_LOGIN,
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
        proto = "https"
        host = self._host
        if "://" in host:
            proto, host = host.split("://", 1)
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

    async def test_connection(self) -> dict[str, Any]:
        """Login and fetch sysinfo to verify the connection works.

        Returns the first sysinfo dict on success.
        """
        await self.login()
        info = await self.get_sysinfo()
        return info[0] if info else {}

    async def close(self) -> None:
        """Close the HTTP session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()
            # Give the SSL transport a moment to shut down cleanly.
            await asyncio.sleep(0.25)
