"""Firmware vulnerability check for cameras.

Two sources:
  * CVE_RULES: known-exploited camera bugs with a firmware build-date
    cut-off taken from the vendor's own advisory. A camera whose firmware
    is dated before the cut-off is affected.
  * CISA's Known Exploited Vulnerabilities (KEV) catalog, downloaded once a
    day. Makers in it without a usable cut-off (Reolink, Amcrest, ...) get a
    maker-level warning: "this maker has bugs being exploited, check yours".

Firmware usually comes from ONVIF GetDeviceInformation, which many cameras
only answer after a login, so "couldn't check" is a normal result.

The only outside request is the KEV download from cisa.gov. Nothing about
the network is sent.
"""
from __future__ import annotations

from datetime import date, timedelta
import json
import logging
import re
import time
from typing import Any

_LOGGER = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REFRESH_EVERY = timedelta(hours=24)
OLD_FIRMWARE_YEARS = 5

# Camera makers we look for in KEV, by the keyword that identifies them in
# a device's vendor / ONVIF manufacturer and in KEV's vendorProject.
KEV_MAKERS: dict[str, tuple[str, ...]] = {
    "Hikvision": ("hikvision",),
    "Dahua": ("dahua",),
    "Reolink": ("reolink",),
    "Amcrest": ("amcrest",),
    "TVT": ("tvt",),
    "GeoVision": ("geovision",),
    "Edimax": ("edimax",),
    "Axis": ("axis",),
    "Vivotek": ("vivotek",),
    "Uniview": ("uniview",),
}

# Known-exploited bugs with a firmware cut-off from the vendor's advisory.
# "before" is the first build date that has the fix (YYYY-MM-DD).
CVE_RULES: list[dict[str, Any]] = [
    {"maker": "Hikvision", "cve": "CVE-2021-36260", "before": "2021-06-28",
     "what": "command injection in the web server; anyone who can reach it can take the camera over",
     "source": "Hikvision HSRC-202109-01 (firmware dated before 210628 is affected)"},
    {"maker": "Hikvision", "cve": "CVE-2017-7921", "before": "2017-01-01", "likely": True,
     "what": "authentication bypass that hands out the admin account and the config",
     "source": "Hikvision HSRC-201703-04 / CISA ICSA-17-124-01 (affected builds 2014-2016, fixed builds from 2017; exact range depends on the model)"},
    {"maker": "Dahua", "cve": "CVE-2021-33044", "before": "2021-06-01",
     "what": "login bypass with a crafted packet",
     "source": "Dahua DHCC-SA-202106-001 (builds before June 2021)"},
    {"maker": "Dahua", "cve": "CVE-2021-33045", "before": "2020-05-01",
     "what": "login bypass with a crafted packet",
     "source": "Dahua DHCC-SA-202106-001 (camera builds before May 2020)"},
]

# Camera entries in the KEV catalog as of 2026-10-16, used until (or if
# never) the live feed has been downloaded.
KEV_FALLBACK: list[dict[str, str]] = [
    {"cveID": "CVE-2017-7921", "vendorProject": "Hikvision", "product": "Multiple Products", "dateAdded": "2026-03-05",
     "vulnerabilityName": "Hikvision Multiple Products Improper Authentication Vulnerability"},
    {"cveID": "CVE-2021-36260", "vendorProject": "Hikvision", "product": "Security cameras web server", "dateAdded": "2022-01-10",
     "vulnerabilityName": "Hikvision Improper Input Validation"},
    {"cveID": "CVE-2021-33044", "vendorProject": "Dahua", "product": "IP Camera Firmware", "dateAdded": "2024-08-21",
     "vulnerabilityName": "Dahua IP Camera Authentication Bypass Vulnerability"},
    {"cveID": "CVE-2021-33045", "vendorProject": "Dahua", "product": "IP Camera Firmware", "dateAdded": "2024-08-21",
     "vulnerabilityName": "Dahua IP Camera Authentication Bypass Vulnerability"},
    {"cveID": "CVE-2021-40407", "vendorProject": "Reolink", "product": "RLC-410W IP Camera", "dateAdded": "2024-12-18",
     "vulnerabilityName": "Reolink RLC-410W IP Camera OS Command Injection Vulnerability"},
    {"cveID": "CVE-2019-11001", "vendorProject": "Reolink", "product": "Multiple IP Cameras", "dateAdded": "2024-12-18",
     "vulnerabilityName": "Reolink Multiple IP Cameras OS Command Injection Vulnerability"},
    {"cveID": "CVE-2020-5735", "vendorProject": "Amcrest", "product": "Cameras and Network Video Recorder (NVR)", "dateAdded": "2021-11-03",
     "vulnerabilityName": "Amcrest Cameras and NVR Stack-based Buffer Overflow Vulnerability"},
    {"cveID": "CVE-2019-20085", "vendorProject": "TVT", "product": "NVMS-1000", "dateAdded": "2021-11-03",
     "vulnerabilityName": "TVT NVMS-1000 Directory Traversal Vulnerability"},
    {"cveID": "CVE-2024-11120", "vendorProject": "GeoVision", "product": "Multiple Devices", "dateAdded": "2025-05-07",
     "vulnerabilityName": "GeoVision Devices OS Command Injection Vulnerability"},
    {"cveID": "CVE-2024-6047", "vendorProject": "GeoVision", "product": "Multiple Devices", "dateAdded": "2025-05-07",
     "vulnerabilityName": "GeoVision Devices OS Command Injection Vulnerability"},
    {"cveID": "CVE-2025-1316", "vendorProject": "Edimax", "product": "IC-7100 IP Camera", "dateAdded": "2025-03-19",
     "vulnerabilityName": "Edimax IC-7100 IP Camera OS Command Injection Vulnerability"},
]

_kev: list[dict[str, str]] = KEV_FALLBACK
_kev_meta: dict[str, Any] = {"source": "bundled", "catalog_version": "2026.10.16", "fetched": 0}

# Xiongmai's "Sofia" firmware (XMEye apps) reports versions like
# "V5.00.R02.000589C9.10010.040200..ONVIF 2.41" and models like "XM530_...",
# often with "H264" as the manufacturer.
_XIONGMAI_FW = re.compile(r"^v\d\.\d{2}\.r\d{2}\.[0-9a-z]{8}\.\d{5}\.")
_XIONGMAI_MODEL = re.compile(r"(?:^|[^a-z0-9])xm\d{3}[_-]")


def _maker_of(*texts: str) -> str | None:
    hay = " ".join(t for t in texts if t).lower()
    for maker, keys in KEV_MAKERS.items():
        if any(re.search(r"\b" + re.escape(k) + r"\b", hay) for k in keys):
            return maker
    return None


def firmware_family(vendor: str, manufacturer: str, model: str, firmware: str) -> str | None:
    """Who made the camera's firmware, from whatever it told us."""
    maker = _maker_of(manufacturer, vendor)
    if maker:
        return maker
    if _XIONGMAI_FW.search((firmware or "").lower()) or _XIONGMAI_MODEL.search((model or "").lower()):
        return "XMEye/Xiongmai"
    return None


def firmware_date(firmware: str) -> date | None:
    """The build date in a firmware string, if it has one.

    Hikvision "V5.5.82 build 190220", Dahua "..., Build Date: 2020-08-20" or
    "V2.820.0000000.33.R.210705", and the common "V1.2.1755-20180813-..."."""
    fw = firmware or ""
    for rx, kind in ((r"build\s*(\d{6})(?!\d)", "yymmdd"),
                     (r"build date:\s*(\d{4})-(\d{2})-(\d{2})", "ymd"),
                     (r"\.r\.(\d{6})(?!\d)", "yymmdd"),
                     (r"(?<!\d)(20\d{2})(\d{2})(\d{2})(?!\d)", "ymd")):
        m = re.search(rx, fw, re.IGNORECASE)
        if not m:
            continue
        try:
            if kind == "yymmdd":
                s = m.group(1)
                return date(2000 + int(s[:2]), int(s[2:4]), int(s[4:]))
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            continue
    return None


def assess(vendor: str = "", manufacturer: str = "", model: str = "", firmware: str = "",
           today: date | None = None) -> dict[str, Any] | None:
    """Vulnerability picture for one device, or None if there's nothing to say.

    findings[].status: "affected" (firmware predates the fix), "likely"
    (predates it, but the affected range depends on the model) or "check"
    (the maker has an exploited bug and we couldn't read the firmware date,
    or there's no version cut-off we can rely on)."""
    family = firmware_family(vendor, manufacturer, model, firmware)
    built = firmware_date(firmware)
    today = today or date.today()
    findings: list[dict[str, Any]] = []
    ruled: set[str] = set()
    for rule in CVE_RULES:
        if rule["maker"] != family:
            continue
        ruled.add(rule["cve"])
        fixed = date.fromisoformat(rule["before"])
        if built is None:
            findings.append({"cve": rule["cve"], "status": "check", "kev": _in_kev(rule["cve"]),
                             "detail": f"{rule['what']}. Firmware dated before {fixed} is affected; "
                                       "this camera didn't report its firmware, so check it by hand.",
                             "source": rule["source"]})
        elif built < fixed:
            findings.append({"cve": rule["cve"], "status": "likely" if rule.get("likely") else "affected",
                             "kev": _in_kev(rule["cve"]),
                             "detail": f"{rule['what']}. Firmware built {built}; fixed builds are dated {fixed} or later.",
                             "source": rule["source"]})
    if family:
        for e in _kev:
            if e["cveID"] in ruled or _maker_of(e.get("vendorProject", "")) != family:
                continue
            findings.append({"cve": e["cveID"], "status": "check", "kev": True,
                             "detail": f"{e.get('vulnerabilityName', '')} ({e.get('product', '')}). "
                                       "CISA lists it as exploited; there's no firmware cut-off to compare "
                                       "against, so check this model by hand.",
                             "source": "CISA Known Exploited Vulnerabilities"})
    age = None
    if built:
        age = (today - built).days // 365
    # Knowing who made the firmware is worth keeping on its own (it drives
    # the vendor advisories), even with nothing found.
    if not family and not findings and not (age is not None and age >= OLD_FIRMWARE_YEARS):
        return None
    return {
        "family": family,
        "firmware": (firmware or "")[:80],
        "firmware_date": built.isoformat() if built else None,
        "firmware_age_years": age,
        "findings": findings,
        "worst": next((s for s in ("affected", "likely", "check") if any(f["status"] == s for f in findings)), None),
    }


def _in_kev(cve: str) -> bool:
    return any(e["cveID"] == cve for e in _kev)


def kev_status() -> dict[str, Any]:
    return {**_kev_meta, "camera_entries": len(_kev)}


def _camera_entries(text: str) -> tuple[list[dict[str, str]], str]:
    """Parse the KEV JSON (run in the executor; it's ~2 MB) down to the
    camera makers we care about."""
    data = json.loads(text)
    keep = []
    for e in data.get("vulnerabilities", []):
        if _maker_of(e.get("vendorProject", "")):
            keep.append({k: str(e.get(k, ""))[:200] for k in
                         ("cveID", "vendorProject", "product", "dateAdded", "vulnerabilityName")})
    return keep, str(data.get("catalogVersion", ""))


class KevFeed:
    """Keeps the camera part of CISA's KEV catalog fresh (once a day)."""

    def __init__(self, hass: Any) -> None:
        from homeassistant.helpers.storage import Store

        self.hass = hass
        self._store = Store(hass, 1, "unifiblocker_kev")
        self._etag = ""
        self._unsub: Any = None

    async def async_load(self) -> None:
        global _kev, _kev_meta  # noqa: PLW0603
        data = await self._store.async_load()
        if isinstance(data, dict) and data.get("entries"):
            _kev = data["entries"]
            _kev_meta = {"source": "cisa", "catalog_version": data.get("catalog_version", ""),
                         "fetched": data.get("fetched", 0)}
            self._etag = data.get("etag", "")

    async def async_refresh(self, _now: Any = None) -> None:
        global _kev, _kev_meta  # noqa: PLW0603
        from homeassistant.helpers.aiohttp_client import async_get_clientsession

        try:
            session = async_get_clientsession(self.hass)
            headers = {"If-None-Match": self._etag} if self._etag else {}
            async with session.get(KEV_URL, headers=headers, timeout=60) as resp:
                if resp.status == 304:
                    _kev_meta["fetched"] = time.time()
                    return
                if resp.status != 200:
                    _LOGGER.debug("KEV download HTTP %s", resp.status)
                    return
                text = await resp.text()
                etag = resp.headers.get("ETag", "")
            entries, version = await self.hass.async_add_executor_job(_camera_entries, text)
        except Exception as err:  # offline or cisa.gov down: keep what we have
            _LOGGER.debug("KEV download failed: %s", err)
            return
        if not entries:
            return
        _kev = entries
        _kev_meta = {"source": "cisa", "catalog_version": version, "fetched": time.time()}
        self._etag = etag
        await self._store.async_save({"entries": entries, "catalog_version": version,
                                      "fetched": _kev_meta["fetched"], "etag": etag})

    def start(self) -> None:
        from homeassistant.helpers.event import async_call_later, async_track_time_interval

        # A couple of minutes after startup, then daily.
        self._unsub = [async_call_later(self.hass, 120, self.async_refresh),
                       async_track_time_interval(self.hass, self.async_refresh, REFRESH_EVERY)]

    def stop(self) -> None:
        for u in self._unsub or []:
            u()
        self._unsub = None
