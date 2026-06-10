"""Crypto miner discovery & profitability tracker.

Discovery is two-pronged:
  1. Port-scan cache — devices fingerprinted as "crypto" (port 4028, 8081,
     Stratum, blockchain P2P) become candidates.
  2. Vendor OUI — devices from known ASIC manufacturers (Goldshell, Bitmain,
     MicroBT/Whatsminer, Canaan/Avalon, Innosilicon, IceRiver) become
     candidates even without a crypto-tagged port (many Goldshell rigs only
     expose port 80 with the proprietary /mcb/ HTTP API).

Each candidate is probed by:
  • CGMiner JSON-RPC on TCP 4028 (Antminer, Whatsminer, Avalon, Braiins OS+)
  • Goldshell HTTP API at /mcb/status + /mcb/cgminer?cgminercmd=devs

Profitability is computed from minerstat.com live coin data (no auth, 10-min
cache) against a fixed electricity cost.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

# ── Tunables ─────────────────────────────────────────────────────────
ELECTRICITY_COST_USD_PER_KWH = 0.08   # 8 cents/kWh
CGMINER_API_PORT = 4028
CGMINER_TIMEOUT = 3.0                 # seconds per command
HTTP_TIMEOUT = 4.0                    # seconds per Goldshell HTTP call
COIN_CACHE_TTL = 600                  # 10 min
MINERSTAT_URL = "https://api.minerstat.com/v2/coins"

# Vendor substrings that mark a client as a likely miner.
MINER_VENDOR_HINTS = (
    "goldshell", "bitmain", "antminer", "microbt", "whatsminer",
    "canaan", "avalon", "innosilicon", "iceriver", "jasminer", "ibelink",
)

# ── Algorithm → coin assumption ──────────────────────────────────────
# block_time_s = seconds between blocks for that chain at current params.
ALGO_COIN: dict[str, dict[str, Any]] = {
    "SHA-256":      {"coin": "BTC",  "block_time_s": 600},
    "Scrypt":       {"coin": "LTC",  "block_time_s": 150},
    "KHeavyHash":   {"coin": "KAS",  "block_time_s": 1},
    "kHeavyHash":   {"coin": "KAS",  "block_time_s": 1},
    "Ethash":       {"coin": "ETC",  "block_time_s": 13},
    "Blake2B-Sia":  {"coin": "SC",   "block_time_s": 600},
    "Blake2BSha3":  {"coin": "KDA",  "block_time_s": 30},
    "Kadena":       {"coin": "KDA",  "block_time_s": 30},
    "Eaglesong":    {"coin": "CKB",  "block_time_s": 11},
    "RandomX":      {"coin": "XMR",  "block_time_s": 120},
    "CryptoNightR": {"coin": "XMR",  "block_time_s": 120},
    "Handshake":    {"coin": "HNS",  "block_time_s": 600},
    "Blake3":       {"coin": "ALPH", "block_time_s": 64},
    "zkSNARK":      {"coin": "ALEO", "block_time_s": 15},
    "SHA3x":        {"coin": "XTM",  "block_time_s": 120},
    "Lbry":         {"coin": "LBC",  "block_time_s": 150},
}

# ── ASIC spec sheet ──────────────────────────────────────────────────
# (model_prefix, algorithm, rated_hashrate_H_per_s, rated_power_W).
# Order matters: longer / more-specific prefixes MUST come before shorter
# ones (e.g. "KD-BOX Pro" before "KD-BOX"). Live hashrate from the API
# overrides the rated figure; rated power is the fallback when the rig
# doesn't expose live wall-power.
ASIC_SPECS: list[tuple[str, str, float, float]] = [
    # ═══════════════════════════════════════════════════════════════
    #  GOLDSHELL  — full catalog (longest names first)
    # ═══════════════════════════════════════════════════════════════
    # — Kadena (KHeavyHash variant, KDA)
    ("KD-BOX Pro",       "Kadena",     2.6e12,  230),
    ("KD-BOX 2",         "Kadena",       5e12,  400),
    ("KD-BOX",           "Kadena",     1.6e12,  205),
    ("KD6-SE",           "Kadena",    25.3e12, 2300),
    ("KD5 Pro",          "Kadena",    24.5e12, 3000),
    ("KD Lite",          "Kadena",    16.2e12, 1330),
    ("KD Max",           "Kadena",    40.2e12, 3350),
    ("KD6",              "Kadena",    29.2e12, 2630),
    ("KD5",              "Kadena",      18e12, 2250),
    ("KD2",              "Kadena",       6e12,  830),
    # — Scrypt (LTC + DOGE merge)
    ("Mini-DOGE III Plus","Scrypt",   810e6,    500),
    ("Mini-DOGE III",    "Scrypt",     700e6,   400),
    ("Mini-DOGE II",     "Scrypt",     420e6,   400),
    ("Mini-DOGE Pro",    "Scrypt",     205e6,   220),
    ("Mini-DOGE",        "Scrypt",     185e6,   233),
    ("E-DG1M",           "Scrypt",     3.4e9,  1800),
    ("DG Card",          "Scrypt",      80e6,    65),
    ("DG Max",           "Scrypt",     6.5e9,  3400),
    ("LT5 Pro",          "Scrypt",    2.45e9,  3100),
    ("LT Lite",          "Scrypt",    1.62e9,  1450),
    ("LT5",              "Scrypt",    2.05e9,  2080),
    ("LT6",              "Scrypt",    3.35e9,  3200),
    ("X5S",              "Scrypt",    1.36e9,  1850),
    ("X5",               "Scrypt",     850e6,  1450),
    # — Handshake (HNS)
    ("HS1-PLUS",         "Handshake",  105e9,   115),
    ("HS-BOX 2",         "Handshake",  460e9,   400),
    ("HS-BOX",           "Handshake",  235e9,   230),
    ("HS3-SE",           "Handshake",  930e9,   930),
    ("HS6-SE",           "Handshake",   3.7e12, 3400),
    ("HS Lite",          "Handshake",  1.36e12, 1250),
    ("HS3",              "Handshake",     2e12, 2000),
    ("HS5",              "Handshake",   2.7e12, 2650),
    ("HS6",              "Handshake",   4.3e12, 3250),
    # — Blake2B-Sia (SC)
    ("SC-BOX 2",         "Blake2B-Sia",  1.9e12,  400),
    ("SC-BOX",           "Blake2B-Sia",  900e9,   200),
    ("SC5 Pro II",       "Blake2B-Sia",   14e12, 3300),
    ("SC5 Pro",          "Blake2B-Sia",   11e12, 2820),
    ("SC6-SE",           "Blake2B-Sia",   17e12, 3300),
    ("SC Lite",          "Blake2B-Sia",  4.4e12,  950),
    # — Eaglesong (CKB)
    ("CK-BOX 2",         "Eaglesong",   2.1e12,  400),
    ("CK-BOX",           "Eaglesong",  1.05e12,  215),
    ("CK6-SE",           "Eaglesong",    17e12, 3300),
    ("CK Lite",          "Eaglesong",   6.3e12, 1200),
    ("CK5",              "Eaglesong",    12e12, 2400),
    ("CK6",              "Eaglesong",  19.3e12, 3300),
    # — KHeavyHash (KAS)
    ("KA-BOX Pro",       "KHeavyHash",  1.6e12,  600),
    ("KA-BOX",           "KHeavyHash", 1.18e12,  400),
    ("E-KA1M",           "KHeavyHash",  5.5e12, 1800),
    # — Blake3 (ALPH)
    ("AL-BOX II Plus",   "Blake3",        1e12,  480),
    ("AL-BOX II Pro",    "Blake3",      950e9,   460),
    ("AL-BOX III",       "Blake3",     1.25e12,  600),
    ("AL-BOX II",        "Blake3",      720e9,   360),
    ("AL-BOX",           "Blake3",      360e9,   180),
    ("AL Max",           "Blake3",      8.3e12, 3350),
    ("E-AL1M",           "Blake3",      4.4e12, 1800),
    # — zkSNARK (ALEO)
    ("AE Max II",        "zkSNARK",     540e6,  3200),
    ("AE Max",           "zkSNARK",     360e6,  3300),
    ("AE-BOX Pro",       "zkSNARK",      44e6,   460),
    ("AE-BOX II",        "zkSNARK",      54e6,   530),
    ("AE-BOX",           "zkSNARK",      37e6,   360),
    ("AE Card",          "zkSNARK",     5.5e6,    65),
    ("E-AE1M",           "zkSNARK",     230e6,  2000),
    ("Byte",             "zkSNARK",     5.5e6,   140),
    # — SHA3x (Tari)
    ("XT-BOX",           "SHA3x",       580e9,   400),
    ("XT Card",          "SHA3x",       100e9,    65),
    # — Lbry (LBC)
    ("LB-BOX",           "Lbry",        175e9,   162),
    ("LB Lite",          "Lbry",       1.62e12, 1450),
    ("LB1",              "Lbry",         87e9,    80),
    # — CryptoNightR (legacy XMR-style)
    ("ST-BOX",           "CryptoNightR", 13.92e3,  61),
    # ═══════════════════════════════════════════════════════════════
    #  BITMAIN (Antminer) — SHA-256, Scrypt, kHeavyHash
    # ═══════════════════════════════════════════════════════════════
    ("Antminer S19 XP",     "SHA-256",  140e12, 3010),
    ("Antminer S19 Pro",    "SHA-256",  110e12, 3250),
    ("Antminer S19j Pro",   "SHA-256",  104e12, 3068),
    ("Antminer S19j",       "SHA-256",  100e12, 3050),
    ("Antminer S19",        "SHA-256",   95e12, 3250),
    ("Antminer S21",        "SHA-256",  200e12, 3500),
    ("Antminer S17 Pro",    "SHA-256",   53e12, 2094),
    ("Antminer S17",        "SHA-256",   56e12, 2200),
    ("Antminer S9",         "SHA-256", 13.5e12, 1323),
    ("Antminer T19",        "SHA-256",   84e12, 3150),
    ("Antminer T17",        "SHA-256",   40e12, 2200),
    ("Antminer L7",         "Scrypt",    9.5e9, 3425),
    ("Antminer L3+",        "Scrypt",    504e6,  800),
    ("Antminer KS5",        "KHeavyHash", 20e12, 3500),
    ("Antminer KS3",        "KHeavyHash", 8.3e12, 3188),
    # ═══════════════════════════════════════════════════════════════
    #  MICROBT / WHATSMINER — SHA-256
    # ═══════════════════════════════════════════════════════════════
    ("Whatsminer M30S++",   "SHA-256", 112e12, 3472),
    ("Whatsminer M30S+",    "SHA-256", 100e12, 3400),
    ("Whatsminer M30S",     "SHA-256",  86e12, 3268),
    ("Whatsminer M50S",     "SHA-256", 126e12, 3276),
    ("Whatsminer M50",      "SHA-256", 118e12, 3306),
    ("Whatsminer M53",      "SHA-256", 226e12, 6554),
    ("Whatsminer M20S",     "SHA-256",  68e12, 3360),
    # ═══════════════════════════════════════════════════════════════
    #  CANAAN / AVALON — SHA-256
    # ═══════════════════════════════════════════════════════════════
    ("Avalon 1346",         "SHA-256", 110e12, 3300),
    ("Avalon 1246",         "SHA-256",  90e12, 3420),
    ("Avalon A12",          "SHA-256",  90e12, 3420),
    # ═══════════════════════════════════════════════════════════════
    #  INNOSILICON — Ethash etc.
    # ═══════════════════════════════════════════════════════════════
    ("Innosilicon A11",     "Ethash",  2.0e9, 2500),
    # ═══════════════════════════════════════════════════════════════
    #  ICERIVER — KHeavyHash
    # ═══════════════════════════════════════════════════════════════
    ("IceRiver KS3",        "KHeavyHash", 8.0e12, 3400),
    ("IceRiver KS2",        "KHeavyHash", 2.0e12, 1200),
    ("IceRiver KS1",        "KHeavyHash", 1.0e12,  432),
    ("IceRiver KS0",        "KHeavyHash", 100e9,    65),
]


def _norm(s: str) -> str:
    """Collapse to alphanumerics, lowercase — for model-name matching."""
    return "".join(c for c in (s or "").lower() if c.isalnum())


def _identify_asic(model_str: str) -> tuple[str, str, float, float] | None:
    """Match a model string against the spec table.

    Tries strict startswith first, then a normalized substring match.
    """
    if not model_str:
        return None
    m = model_str.strip()
    m_norm = _norm(m)
    # Strict prefix first.
    for prefix, algo, hr, power in ASIC_SPECS:
        if m.lower().startswith(prefix.lower()):
            return prefix, algo, hr, power
    # Normalized substring (catches "KDBOX_PRO", "kd_box_pro" → "KD-BOX Pro").
    for prefix, algo, hr, power in ASIC_SPECS:
        if _norm(prefix) in m_norm:
            return prefix, algo, hr, power
    return None


# ── CGMiner JSON-RPC client (TCP 4028) ───────────────────────────────

async def _cgminer_cmd(ip: str, command: str) -> dict[str, Any] | None:
    """Send a single CGMiner API command and return the parsed reply."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, CGMINER_API_PORT),
            timeout=CGMINER_TIMEOUT,
        )
        writer.write(json.dumps({"command": command}).encode())
        await writer.drain()
        try:
            writer.write_eof()
        except (OSError, NotImplementedError):
            pass
        raw = await asyncio.wait_for(reader.read(65536), timeout=CGMINER_TIMEOUT)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        text = raw.decode(errors="ignore").rstrip("\x00").strip()
        return json.loads(text) if text else None
    except (asyncio.TimeoutError, OSError, json.JSONDecodeError) as err:
        _LOGGER.debug("CGMiner API %s on %s failed: %s", command, ip, err)
        return None


async def _probe_cgminer(ip: str) -> dict[str, Any] | None:
    """Query a rig over the standard CGMiner JSON-RPC API."""
    summary, version, stats = await asyncio.gather(
        _cgminer_cmd(ip, "summary"),
        _cgminer_cmd(ip, "version"),
        _cgminer_cmd(ip, "stats"),
    )
    if not summary and not version:
        return None

    model = ""
    if version and "VERSION" in version and version["VERSION"]:
        v = version["VERSION"][0]
        model = v.get("Type") or v.get("Miner") or v.get("API") or ""

    hashrate_hs = 0.0
    if summary and "SUMMARY" in summary and summary["SUMMARY"]:
        s = summary["SUMMARY"][0]
        for key, mult in [
            ("THS 5s", 1e12), ("THS av", 1e12),
            ("GHS 5s", 1e9),  ("GHS av", 1e9),
            ("MHS 5s", 1e6),  ("MHS av", 1e6),
            ("KHS 5s", 1e3),  ("KHS av", 1e3),
        ]:
            val = s.get(key)
            if val:
                try:
                    hashrate_hs = float(val) * mult
                    break
                except (TypeError, ValueError):
                    pass

    live_power_w = 0.0
    if stats and "STATS" in stats:
        for entry in stats["STATS"]:
            for key in ("Power", "power", "power_consume", "Power_RT"):
                if key in entry:
                    try:
                        live_power_w = float(entry[key])
                        break
                    except (TypeError, ValueError):
                        pass
            if live_power_w:
                break

    return {
        "source": "cgminer",
        "model_reported": model,
        "hashrate_hs": hashrate_hs,
        "live_power_w": live_power_w,
        "extras": {},
    }


# ── Goldshell HTTP API (/mcb/ on port 80) ───────────────────────────

# Models report hashrate in units that depend on the algorithm. Map the
# /mcb/status model string → unit multiplier (H/s per reported unit).
def _goldshell_unit_for_algo(algo: str) -> float:
    if algo in ("SHA-256",):
        return 1e12  # TH/s (none of these in Goldshell catalog, but safe)
    if algo in ("Kadena", "Blake2B-Sia", "Eaglesong", "KHeavyHash", "Blake3"):
        return 1e9   # GH/s reported
    if algo in ("Handshake", "SHA3x", "Lbry"):
        return 1e9   # GH/s reported
    if algo in ("Scrypt", "zkSNARK"):
        return 1e6   # MH/s reported
    if algo in ("CryptoNightR",):
        return 1e3   # KH/s reported
    return 1.0       # raw H/s fallback


async def _probe_goldshell(session: aiohttp.ClientSession, ip: str) -> dict[str, Any] | None:
    """Query a rig over the Goldshell /mcb/ HTTP API."""
    timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
    model = firmware = hardware = ""
    try:
        async with session.get(f"http://{ip}/mcb/status", timeout=timeout) as resp:
            if resp.status != 200:
                return None
            status = await resp.json(content_type=None)
        model = str(status.get("model") or "")
        firmware = str(status.get("firmware") or "")
        hardware = str(status.get("hardware") or "")
        if not model:
            return None
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
        return None

    # Need to know algo before we can scale hashrate units, so identify first.
    ident = _identify_asic(model)
    algo = ident[1] if ident else ""
    unit_mult = _goldshell_unit_for_algo(algo)

    hashrate_hs = 0.0
    temp_c = 0.0
    fanspeed = 0
    try:
        async with session.get(
            f"http://{ip}/mcb/cgminer?cgminercmd=devs",
            timeout=timeout,
        ) as resp:
            if resp.status == 200:
                devs = await resp.json(content_type=None)
                # Response shape: {"data": [{"hashrate": x, "av_hashrate": y, "temp": z, ...}, ...]}
                # Goldshell rigs with multiple boards return one entry per board — sum them.
                data = devs.get("data") if isinstance(devs, dict) else None
                if isinstance(data, list):
                    for d in data:
                        for k in ("hashrate", "av_hashrate"):
                            v = d.get(k)
                            if v is not None:
                                try:
                                    hashrate_hs += float(v) * unit_mult
                                    break  # one hashrate per board
                                except (TypeError, ValueError):
                                    pass
                        try:
                            temp_c = max(temp_c, float(d.get("temp") or 0))
                        except (TypeError, ValueError):
                            pass
                        try:
                            fanspeed = max(fanspeed, int(d.get("fanspeed") or 0))
                        except (TypeError, ValueError):
                            pass
    except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as err:
        _LOGGER.debug("Goldshell devs query failed on %s: %s", ip, err)

    return {
        "source": "goldshell",
        "model_reported": model,
        "hashrate_hs": hashrate_hs,
        "live_power_w": 0.0,  # Goldshell doesn't expose wall power
        "extras": {
            "firmware": firmware,
            "hardware": hardware,
            "temp_c": round(temp_c, 1) if temp_c else 0,
            "fanspeed_pct": fanspeed,
        },
    }


async def _query_rig(session: aiohttp.ClientSession, ip: str) -> dict[str, Any] | None:
    """Try every supported miner protocol; return the first that answers."""
    # Race both probes — first non-None wins. cgminer typically responds
    # in <100ms when present; Goldshell HTTP in ~200-500ms.
    cgminer_task = asyncio.create_task(_probe_cgminer(ip))
    goldshell_task = asyncio.create_task(_probe_goldshell(session, ip))
    try:
        result = await cgminer_task
        if result and result["model_reported"]:
            goldshell_task.cancel()
            return result
        result_g = await goldshell_task
        if result_g:
            return result_g
        return result  # may be cgminer with empty model — better than nothing
    except Exception:
        goldshell_task.cancel()
        cgminer_task.cancel()
        return None


# ── Minerstat coin data ──────────────────────────────────────────────

class _CoinCache:
    """10-minute cache of minerstat.com coin data."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._fetched_at: float = 0.0

    async def get(self, session: aiohttp.ClientSession) -> dict[str, dict[str, Any]]:
        if self._data and time.time() - self._fetched_at < COIN_CACHE_TTL:
            return self._data
        try:
            wanted = ",".join(sorted({c["coin"] for c in ALGO_COIN.values()}))
            async with session.get(
                MINERSTAT_URL,
                params={"list": wanted},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                resp.raise_for_status()
                rows = await resp.json()
            self._data = {row["coin"]: row for row in rows if row.get("coin")}
            self._fetched_at = time.time()
        except Exception as err:
            _LOGGER.warning("minerstat fetch failed: %s", err)
        return self._data


# ── Profitability calc ──────────────────────────────────────────────

def _profit(rig_hashrate_hs: float, power_w: float, coin_row: dict[str, Any],
            block_time_s: float) -> dict[str, float]:
    """Return revenue/cost/profit in USD per day."""
    try:
        net_hr = float(coin_row.get("network_hashrate") or 0)
        reward = float(coin_row.get("reward_block") or 0)
        price = float(coin_row.get("price") or 0)
    except (TypeError, ValueError):
        net_hr = reward = price = 0.0

    if net_hr <= 0 or rig_hashrate_hs <= 0 or block_time_s <= 0:
        revenue_day = 0.0
    else:
        blocks_per_day = 86400.0 / block_time_s
        share = rig_hashrate_hs / net_hr
        revenue_day = share * reward * blocks_per_day * price

    cost_day = (power_w / 1000.0) * 24.0 * ELECTRICITY_COST_USD_PER_KWH
    return {
        "revenue_usd_day": round(revenue_day, 4),
        "cost_usd_day": round(cost_day, 4),
        "profit_usd_day": round(revenue_day - cost_day, 4),
        "coin_price_usd": round(price, 2),
    }


# ── Tracker ──────────────────────────────────────────────────────────

def _format_hashrate(hs: float) -> str:
    if hs <= 0:
        return "—"
    if hs >= 1e12:
        return f"{hs/1e12:.2f} TH/s"
    if hs >= 1e9:
        return f"{hs/1e9:.2f} GH/s"
    if hs >= 1e6:
        return f"{hs/1e6:.2f} MH/s"
    if hs >= 1e3:
        return f"{hs/1e3:.2f} kH/s"
    return f"{hs:.0f} H/s"


def _is_miner_vendor(vendor: str) -> bool:
    v = (vendor or "").lower()
    return any(hint in v for hint in MINER_VENDOR_HINTS)


class MinerTracker:
    """Discovers miners and tracks live profitability."""

    def __init__(self, scanner: Any) -> None:
        self._scanner = scanner
        self._coins = _CoinCache()
        self._last: list[dict[str, Any]] = []

    @property
    def rigs(self) -> list[dict[str, Any]]:
        return self._last

    def _candidates(self, clients: list[dict[str, Any]] | None) -> dict[str, str]:
        """Return {mac: ip} for every plausible miner."""
        out: dict[str, str] = {}

        # 1. Port-scan cache: anything fingerprinted as crypto, or with the
        #    cgminer port open.
        if self._scanner:
            for mac, entry in (self._scanner.cache or {}).items():
                if entry.get("status") != "complete":
                    continue
                ip = entry.get("ip", "")
                if not ip:
                    continue
                groups = set(entry.get("groups_found") or [])
                ports = set(entry.get("open_ports") or [])
                if (entry.get("guess_category") == "crypto"
                        or "crypto" in groups
                        or CGMINER_API_PORT in ports):
                    out[mac] = ip

        # 2. Vendor OUI: any client from a known miner manufacturer, even
        #    if the port scanner missed it (Goldshell on port 80 only).
        for c in clients or []:
            mac = (c.get("mac") or "").lower()
            ip = c.get("ip") or ""
            if not mac or not ip or mac in out:
                continue
            if _is_miner_vendor(c.get("oui") or ""):
                out[mac] = ip

        return out

    async def async_update(
        self,
        session: aiohttp.ClientSession,
        clients: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        targets = self._candidates(clients)
        if not targets:
            self._last = []
            return self._last

        macs = list(targets.keys())
        probes = await asyncio.gather(
            *(_query_rig(session, targets[mac]) for mac in macs),
            return_exceptions=True,
        )
        probe_by_mac = dict(zip(macs, probes))

        coin_data = await self._coins.get(session)

        rigs: list[dict[str, Any]] = []
        for mac, ip in targets.items():
            probe = probe_by_mac.get(mac)
            if isinstance(probe, Exception) or not probe:
                rigs.append({
                    "mac": mac, "ip": ip, "reachable": False,
                    "source": "", "model": "", "model_reported": "",
                    "algorithm": "", "coin": "",
                    "hashrate_hs": 0, "hashrate_display": "—",
                    "power_w": 0, "power_source": "",
                    "revenue_usd_day": 0, "cost_usd_day": 0,
                    "profit_usd_day": 0, "coin_price_usd": 0,
                    "extras": {},
                })
                continue

            model_str = probe["model_reported"]
            ident = _identify_asic(model_str)
            if ident:
                model, algo, _rated_hr, rated_power = ident
            else:
                model = model_str or "Unknown miner"
                algo = ""
                rated_power = 0.0

            power_w = probe["live_power_w"] or rated_power
            coin_info = ALGO_COIN.get(algo, {})
            coin = coin_info.get("coin", "")
            block_time = coin_info.get("block_time_s", 0)
            coin_row = coin_data.get(coin, {}) if coin else {}

            calc = _profit(probe["hashrate_hs"], power_w, coin_row, block_time)
            rigs.append({
                "mac": mac, "ip": ip, "reachable": True,
                "source": probe["source"],
                "model": model, "model_reported": model_str,
                "algorithm": algo, "coin": coin,
                "hashrate_hs": probe["hashrate_hs"],
                "hashrate_display": _format_hashrate(probe["hashrate_hs"]),
                "power_w": round(power_w, 1),
                "power_source": "live" if probe["live_power_w"] else "rated",
                "extras": probe.get("extras") or {},
                **calc,
            })

        self._last = rigs
        return rigs
