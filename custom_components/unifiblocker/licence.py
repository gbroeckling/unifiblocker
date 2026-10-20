"""UniFi Blocker Pro: the licence key, and the one answer "is this Pro?".

Keys come from the same licence server as traks, GideonMail and PadSpan
(traks.ca/license, product=unifiblocker): UBLOK-XXXX-XXXX-XXXX-XXXX, bought
through PayPal on unifiblocker.enerx.ca/pro/, emailed by the server.

The rules, the same as PadSpan's:

- Pro gates starting things, never what is already there. A lapsed licence
  stops new Pro actions; rules already on the controller stay, and turning
  a Pro feature OFF always works. A security tool that opened the network
  back up because a card expired would be doing harm.
- PRO_GRACE_DAYS past expiry it still counts as active: an offline house, a
  card that failed on renewal day, the gap before the daily re-check.
- The daily re-check only ever writes a new expiry. An unreachable server
  changes nothing. A server that says the key is no longer valid sets the
  expiry to now, so the grace period still applies.
- An expiry we can't read is not evidence someone stopped paying: active.
- The key never goes to the browser except to an admin who asks for it.

The server answers for any product it doesn't know as if it were traks, so
a key or trial key that isn't UBLOK-... is refused here whatever the server
says.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

PRODUCT = "unifiblocker"
LICENCE_URL = "https://traks.ca/license/"
BUY_URL = "https://unifiblocker.enerx.ca/pro/"
PRICE = "$35 CAD/year"
PRO_GRACE_DAYS = 14
TRIAL_DAYS = 30
KEY_RE = re.compile(r"^UBLOK(-[A-HJ-NP-Z2-9]{4}){4}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")
REVALIDATE_EVERY = timedelta(days=1)
STORE_KEY = "unifiblocker_licence"


def _iso(value: Any) -> str:
    """The server's "2027-10-20 09:00:00" (UTC) as ISO with a zone."""
    v = str(value or "").strip()
    try:
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return v
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat()


def clean_key(key: str) -> str:
    return re.sub(r"\s+", "", str(key or "")).upper()


def expiry_state(key: str, expires: str, now: datetime | None = None) -> dict[str, Any]:
    """{has_key, active, expires, days_left, in_grace} for a stored key."""
    has_key = bool(key)
    out = {"has_key": has_key, "active": has_key, "expires": expires, "days_left": None, "in_grace": False}
    if not (has_key and expires):
        return out
    try:
        exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        return out  # unreadable: not evidence of anything
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    left = exp - (now or datetime.now(timezone.utc))
    out["days_left"] = left.days
    out["active"] = left > -timedelta(days=PRO_GRACE_DAYS)
    out["in_grace"] = out["active"] and left < timedelta(0)
    return out


class Licence:
    """The install's key, kept in its own store (one per Home Assistant)."""

    def __init__(self, hass: Any) -> None:
        self.hass = hass
        self._store = Store(hass, 1, STORE_KEY)
        self._data: dict[str, Any] = {}
        self._unsub: list | None = None

    async def async_load(self) -> None:
        self._data = await self._store.async_load() or {}

    async def _save(self) -> None:
        await self._store.async_save(self._data)

    # ── state ──────────────────────────────────────────────────────────

    @property
    def key(self) -> str:
        return str(self._data.get("key") or "")

    def state(self) -> dict[str, Any]:
        """Everything the panel may know (no key)."""
        st = expiry_state(self.key, str(self._data.get("expires") or ""))
        return {**st, "pro": st["active"], "trial": bool(self._data.get("trial")) and st["has_key"],
                "trial_used": bool(self._data.get("trial_used")),
                "price": PRICE, "buy_url": BUY_URL, "trial_days": TRIAL_DAYS, "grace_days": PRO_GRACE_DAYS}

    @property
    def pro(self) -> bool:
        return self.state()["active"]

    # ── talking to the licence server ──────────────────────────────────

    async def _machine(self) -> str:
        try:
            from homeassistant.helpers.instance_id import async_get
            return await async_get(self.hass)
        except Exception:
            return "unifiblocker"

    async def _call(self, method: str, params: dict[str, str], data: dict[str, str] | None = None) -> dict[str, Any]:
        from homeassistant.helpers.aiohttp_client import async_get_clientsession
        session = async_get_clientsession(self.hass)
        async with session.request(method, LICENCE_URL, params={**params, "product": PRODUCT}, data=data,
                                   timeout=15) as resp:
            text = await resp.text()
        reply = json.loads(text.lstrip("﻿"))  # the server starts its JSON with a BOM
        return reply if isinstance(reply, dict) else {}

    async def activate(self, key: str) -> dict[str, Any]:
        key = clean_key(key)
        if not KEY_RE.match(key):
            return {"ok": False, "message": "That isn't a UniFi Blocker key. They look like UBLOK-XXXX-XXXX-XXXX-XXXX."}
        try:
            reply = await self._call("GET", {"action": "validate", "key": key, "machine": await self._machine()})
        except Exception as err:
            return {"ok": False, "message": f"Couldn't reach the licence server ({err}). Check the internet connection and try again."}
        if not reply.get("valid"):
            return {"ok": False, "status": reply.get("status") or "invalid",
                    "message": reply.get("message") or "That key isn't valid for UniFi Blocker Pro."}
        self._data.update(key=key, expires=_iso(reply.get("expires_at")), trial=reply.get("plan") == "trial")
        await self._save()
        _LOGGER.info("UniFi Blocker Pro activated (valid until %s)", self._data["expires"] or "no end date")
        return {"ok": True, **self.state()}

    async def start_trial(self, email: str) -> dict[str, Any]:
        email = str(email or "").strip()
        if not _EMAIL_RE.match(email):
            return {"ok": False, "message": "Type a real email address: the trial key is sent there too."}
        if self.key:
            return {"ok": False, "message": "This install already has a key."}
        try:
            reply = await self._call("POST", {"action": "trial_start"}, {"email": email, "machine": await self._machine()})
        except Exception as err:
            return {"ok": False, "message": f"Couldn't reach the licence server ({err}). Try again later."}
        key = clean_key(reply.get("key") or "")
        if not reply.get("ok") or not KEY_RE.match(key):
            return {"ok": False, "status": reply.get("status") or "unavailable",
                    "message": reply.get("message") or "Couldn't start a trial for this install."}
        self._data.update(key=key, expires=_iso(reply.get("expires_at")), trial=True, trial_used=True)
        await self._save()
        return {"ok": True, **self.state()}

    async def remove(self) -> None:
        self._data.pop("key", None)
        self._data.pop("expires", None)
        self._data.pop("trial", None)
        await self._save()

    async def async_revalidate(self, _now: Any = None) -> None:
        """Daily: pick up a renewal (new expiry) or a refund. Only ever
        writes a new expiry; never clears the key."""
        if not self.key:
            return
        try:
            reply = await self._call("GET", {"action": "validate", "key": self.key, "machine": await self._machine()})
        except Exception as err:
            _LOGGER.debug("Licence re-check skipped (%s)", err)
            return
        expires = _iso(reply.get("expires_at"))
        if reply.get("valid"):
            changed = False
            if expires and expires != self._data.get("expires"):
                self._data["expires"] = expires
                changed = True
            if "plan" in reply and (reply.get("plan") == "trial") != bool(self._data.get("trial")):
                self._data["trial"] = reply.get("plan") == "trial"
                changed = True
            if changed:
                await self._save()
        elif reply.get("valid") is False:
            now = datetime.now(timezone.utc)
            st = expiry_state(self.key, str(self._data.get("expires") or ""), now)
            if st["days_left"] is None or st["days_left"] >= 0:
                self._data["expires"] = now.isoformat()  # the grace period still applies from today
                await self._save()
                _LOGGER.warning("The licence server says this UniFi Blocker key is no longer valid (%s)", reply.get("status"))

    def start(self) -> None:
        from homeassistant.helpers.event import async_call_later, async_track_time_interval
        self._unsub = [async_call_later(self.hass, 300, self.async_revalidate),
                       async_track_time_interval(self.hass, self.async_revalidate, REVALIDATE_EVERY)]

    def stop(self) -> None:
        for u in self._unsub or []:
            u()
        self._unsub = None


def licence_of(hass: Any) -> Licence | None:
    # Its own slot, not under hass.data[DOMAIN]: code there loops over
    # config entries and expects nothing else.
    return getattr(hass, "data", {}).get(STORE_KEY) if hass else None


def is_pro(hass: Any) -> bool:
    """The one gate every Pro feature asks."""
    lic = licence_of(hass)
    return bool(lic and lic.pro)
