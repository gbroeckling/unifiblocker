"""What current UniFi Network firmware can tell us that stat/event and DPI
no longer do: the security log, hourly traffic per client, UniFi's own
device fingerprint, and Wi-Fi networks around us.

All pure functions over API rows, so they're easy to test.
"""
from __future__ import annotations

import re
import statistics
import time
from typing import Any

HOUR_MS = 3600_000

# ── security log ─────────────────────────────────────────────────────────


def _fill(template: str, params: dict[str, Any]) -> str:
    """'{SRC_CLIENT} was blocked from accessing {DST_IP}' -> names filled in."""
    def sub(m: re.Match) -> str:
        p = params.get(m.group(1)) or {}
        return str(p.get("name") or p.get("id") or m.group(0))
    return re.sub(r"\{([A-Z_]+)\}", sub, template or "")


def security_events(log: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """SECURITY entries from system-log/all, in the old stat/event shape
    (key/msg/time/src_ip/dst_ip/catname/inner_alert_severity) plus the MAC,
    so the threat sensor and panel keep working."""
    out = []
    for e in log or []:
        if e.get("category") != "SECURITY":
            continue
        params = e.get("parameters") or {}
        src = params.get("SRC_CLIENT") or {}
        dst = params.get("DST_IP") or {}
        out.append({
            "key": e.get("key", ""),
            "msg": _fill(e.get("message_raw", ""), params) or e.get("title_raw", ""),
            "title": e.get("title_raw", ""),
            "time": e.get("timestamp"),
            "mac": str(src.get("id", "")).lower(),
            "src_ip": src.get("ip", ""),
            "dst_ip": dst.get("name") or dst.get("id", ""),
            "catname": e.get("subcategory") or e.get("type", ""),
            "inner_alert_severity": (e.get("severity") or "").lower(),
            "rule": (params.get("TRIGGER") or {}).get("name", ""),
            "source": "system_log",
        })
        # Blocked by one of our own "UB: <mac> ..." rules: that's the
        # containment working, not a threat.
        out[-1]["ours"] = out[-1]["rule"].lower().startswith("ub:")
    out.sort(key=lambda x: x.get("time") or 0, reverse=True)
    return out


def events_by_mac(events: list[dict[str, Any]], ours: bool = False) -> dict[str, int]:
    """Per-MAC count of security events: UniFi's own (ours=False) or blocks
    made by our local-only rules (ours=True)."""
    counts: dict[str, int] = {}
    for e in events:
        if e.get("mac") and bool(e.get("ours")) == ours:
            counts[e["mac"]] = counts.get(e["mac"], 0) + 1
    return counts


# ── traffic history ──────────────────────────────────────────────────────


def hourly_series(rows: list[dict[str, Any]], hours: int = 24,
                  now_ms: int | None = None) -> dict[str, list[int]]:
    """mac -> total bytes per hour for the last *hours* hours, oldest first.
    (UniFi's rx/tx direction isn't reliable across firmware, so this is
    rx+tx.)"""
    now_ms = now_ms or int(time.time() * 1000)
    end = now_ms - now_ms % HOUR_MS          # start of the current hour
    start = end - hours * HOUR_MS
    out: dict[str, list[int]] = {}
    for r in rows or []:
        mac = str(r.get("user", "")).lower()
        t = int(r.get("time") or 0)
        if not mac or t < start or t >= end:
            continue
        i = (t - start) // HOUR_MS
        series = out.setdefault(mac, [0] * hours)
        series[i] += int((r.get("rx_bytes") or 0) + (r.get("tx_bytes") or 0))
    return out


SPIKE_MIN_BYTES = 50_000_000      # never call anything under 50 MB/h a spike
SPIKE_FACTOR = 5


def traffic_spike(series: list[int]) -> dict[str, Any] | None:
    """The last full hour against the usual hourly level of the day before."""
    if not series or len(series) < 6:
        return None
    last, earlier = series[-1], [x for x in series[:-1] if x > 0]
    if last < SPIKE_MIN_BYTES:
        return None
    usual = statistics.median(earlier) if earlier else 0
    if usual and last < usual * SPIKE_FACTOR:
        return None
    return {"last_hour_bytes": last, "usual_bytes": int(usual),
            "factor": round(last / usual, 1) if usual else None}


# ── UniFi's own fingerprint ──────────────────────────────────────────────

# UniFi fingerprint categories (stat/sta dev_cat) that only ever showed up on
# IP cameras on the network this was built against (102 clients: 7 cameras
# had 9, 3 had 57, nothing else had either). It's one more piece of
# evidence, not proof, so it ranks below ONVIF, ports and vendor.
UNIFI_CAMERA_DEV_CATS = frozenset({9, 57})


def unifi_fingerprint(client: dict[str, Any]) -> dict[str, Any] | None:
    if client.get("dev_cat") is None and not client.get("os_name"):
        return None
    return {
        "dev_cat": client.get("dev_cat"),
        "dev_family": client.get("dev_family"),
        "dev_vendor": client.get("dev_vendor"),
        "os_name": client.get("os_name"),
        "camera": client.get("dev_cat") in UNIFI_CAMERA_DEV_CATS,
    }


# ── Wi-Fi networks around us ─────────────────────────────────────────────

# Setup / AP-mode network names cheap cameras broadcast.
_CAMERA_SSID = re.compile(
    r"(?i)^(?:ipc|ipcam|hipc|escam|wansview|ezviz|imou|reolink|annke|dahua|hik(?:vision)?|"
    r"sricam|vstarcam|jooan|tapo[ _-]?c\d|xm[_-]|cam[_-]|camera[_-]|yi[_-]|mv\d+[_-])"
)


def _mac_int(mac: str) -> int | None:
    try:
        return int(mac.replace(":", "").replace("-", ""), 16)
    except ValueError:
        return None


def camera_hotspots(rogue: list[dict[str, Any]], cameras: dict[str, str]) -> list[dict[str, Any]]:
    """Wi-Fi networks that look like a camera's own access point.

    Either the name is a camera setup network (IPC-..., XM_..., EZVIZ_...),
    or the BSSID sits right next to the MAC of one of *our* cameras
    (mac -> name), which means that camera still has its own AP switched on
    while it's on your network."""
    cam_ints = {m: _mac_int(m) for m in cameras}
    out = []
    for ap in rogue or []:
        essid = ap.get("essid") or ""
        bssid = str(ap.get("bssid", "")).lower()
        b = _mac_int(bssid)
        reason = None
        own = None
        if b is not None:
            for mac, n in cam_ints.items():
                if n is not None and (n >> 8) == (b >> 8) and abs((n & 0xFF) - (b & 0xFF)) <= 3:
                    own = mac
                    break
        if own:
            reason = "own_camera"
        elif _CAMERA_SSID.search(essid):
            reason = "camera_ssid"
        if not reason:
            continue
        out.append({
            "essid": essid[:32], "bssid": bssid, "rssi": ap.get("rssi"), "signal": ap.get("signal"),
            "channel": ap.get("channel"), "security": (ap.get("security") or "")[:40],
            "last_seen": ap.get("last_seen"), "reason": reason,
            "camera_mac": own, "camera_name": cameras.get(own, "") if own else "",
        })
    out.sort(key=lambda h: (h["reason"] != "own_camera", -(h.get("rssi") or 0)))
    return out


# ── phone-home monitor (traffic flows) ───────────────────────────────────

# Domain suffix -> whose cloud it is. Camera clouds plus the common
# home-automation ones.
CLOUD_DOMAINS: dict[str, str] = {
    "secu100.net": "Xiongmai (XMEye)", "xmeye.net": "Xiongmai (XMEye)", "xmcsrv.net": "Xiongmai (XMEye)",
    "nseye.com": "Xiongmai (XMEye)", "eseecloud.com": "Xiongmai (XMEye)",
    "hik-connect.com": "Hikvision", "hikvision.com": "Hikvision", "ezvizlife.com": "EZVIZ (Hikvision)",
    "ezviz7.com": "EZVIZ (Hikvision)", "easy4ip.com": "Dahua / Imou", "dahuatech.com": "Dahua",
    "imoulife.com": "Imou (Dahua)", "reolink.com": "Reolink", "reolink.cloud": "Reolink",
    "foscam.com": "Foscam", "myfoscam.com": "Foscam",
    "tuyaus.com": "Tuya / Smart Life", "tuyaeu.com": "Tuya / Smart Life", "tuyacn.com": "Tuya / Smart Life",
    "tuyain.com": "Tuya / Smart Life", "iotbing.com": "Tuya / Smart Life",
    "tplinkcloud.com": "TP-Link Kasa/Tapo", "tplinknbu.com": "TP-Link Kasa/Tapo", "tapo.com": "TP-Link Kasa/Tapo",
    "govee.com": "Govee", "coolkit.cc": "eWeLink (Sonoff)", "ewelink.cc": "eWeLink (Sonoff)",
    "mi.com": "Xiaomi", "xiaomi.com": "Xiaomi", "miot-spec.org": "Xiaomi", "aqara.com": "Aqara",
    "wyze.com": "Wyze", "wyzecam.com": "Wyze", "meross.com": "Meross", "broadlink.com.cn": "Broadlink",
    "ibroadlink.com": "Broadlink", "ring.com": "Ring (Amazon)", "eufylife.com": "Eufy (Anker)",
    "roborock.com": "Roborock", "ecouser.net": "Ecovacs", "dreame.tech": "Dreame",
}
# Public resolvers. Reaching these directly means the device ignores the DNS
# your network hands out (and any filtering on it).
PUBLIC_DNS = {
    "dns.google": "Google DNS", "8.8.8.8": "Google DNS", "8.8.4.4": "Google DNS",
    "one.one.one.one": "Cloudflare DNS", "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "dns.quad9.net": "Quad9", "9.9.9.9": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "114.114.114.114": "114DNS (China)", "223.5.5.5": "AliDNS (China)", "119.29.29.29": "DNSPod (China)",
    "180.76.76.76": "Baidu DNS (China)",
}
PORT_SWEEP_MIN = 5   # this many different ports on one server = hunting for a way out


def _cloud_of(host: str) -> str | None:
    host = (host or "").lower().rstrip(".")
    for suffix, who in CLOUD_DOMAINS.items():
        if host == suffix or host.endswith("." + suffix):
            return who
    return None


def summarize_flows(flows: list[dict[str, Any]]) -> dict[str, Any] | None:
    """One device's logged flows -> what it tried to reach and what stopped it."""
    if not flows:
        return None
    attempts = blocked = allowed = 0
    dests: dict[str, dict[str, Any]] = {}
    regions: dict[str, int] = {}
    clouds: dict[str, int] = {}
    dns: dict[str, int] = {}
    ours = 0
    times = []
    ports_by_host: dict[str, set] = {}
    for f in flows:
        n = int(f.get("count") or 1)
        attempts += n
        if f.get("action") == "blocked":
            blocked += n
        else:
            allowed += n
        d = f.get("destination") or {}
        host = (d.get("domains") or [None])[0] or d.get("ip") or "?"
        key = f"{host}:{d.get('port')}"
        e = dests.setdefault(key, {"host": host, "port": d.get("port"), "region": d.get("region") or "",
                                   "protocol": f.get("protocol", ""), "count": 0})
        e["count"] += n
        if d.get("region"):
            regions[d["region"]] = regions.get(d["region"], 0) + n
        for h in (d.get("domains") or []) + [d.get("ip") or ""]:
            who = _cloud_of(h)
            if who:
                clouds[who] = clouds.get(who, 0) + n
                break
        # DNS only means port 53/853: pinging 8.8.8.8 is a connectivity
        # check, not a DNS lookup.
        if d.get("port") in (53, 853):
            label = PUBLIC_DNS.get(host) or PUBLIC_DNS.get(d.get("ip") or "") or f"DNS server {d.get('ip') or host}"
            dns[label] = dns.get(label, 0) + n
        ports_by_host.setdefault(d.get("ip") or host, set()).add(d.get("port"))
        if any(str(p.get("name", "")).lower().startswith("ub:") for p in f.get("policies") or []):
            ours += n
        if f.get("time"):
            times.append(int(f["time"]))
    top = sorted(dests.values(), key=lambda x: -x["count"])[:6]
    span_min = round((max(times) - min(times)) / 60000) if len(times) > 1 else None
    sweep_host, sweep_ports = max(((h, len(p - {None})) for h, p in ports_by_host.items()),
                                  key=lambda x: x[1], default=(None, 0))
    return {
        "attempts": attempts, "blocked": blocked, "allowed": allowed,
        "blocked_by_our_rule": ours, "window_minutes": span_min,
        "top_destinations": top, "regions": dict(sorted(regions.items(), key=lambda x: -x[1])[:5]),
        "clouds": clouds, "dns_bypass": dns,
        "port_sweep": {"host": sweep_host, "ports": sweep_ports} if sweep_ports >= PORT_SWEEP_MIN else None,
    }


def containment_status(summary: dict[str, Any] | None, contained: bool) -> str | None:
    """For a device that's meant to be cut off from the internet:
    "leaking" if UniFi logged traffic it let through, "holding" if it logged
    blocked attempts, "quiet" if nothing was logged at all."""
    if not contained:
        return None
    if not summary:
        return "quiet"
    return "leaking" if summary["allowed"] else "holding"
