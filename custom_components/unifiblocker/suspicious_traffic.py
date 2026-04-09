"""Suspicious traffic analyzer for UniFi clients.

Scores each client on multiple heuristics to surface devices that warrant
review.  The score is additive — each flag that fires adds points.  A device
with score >= SUSPICIOUS_THRESHOLD is tagged suspicious.

Heuristics
──────────
1. Randomized / locally-administered MAC  (bit 1 of first octet is set)
2. Unknown vendor  (not in the OUI table)
3. No hostname reported
4. First seen very recently  (within last 10 minutes)
5. Extremely high bandwidth  (> configurable MB in the current session)
6. Very short uptime  (connected < 2 min — probe / hit-and-run)
7. Anomalous signal  (very weak signal, could be distance / spoofed)
8. Device was already blocked once on the controller
9. Guest network with high traffic  (data exfiltration pattern)
10. Randomized MAC + unknown vendor combo  (strong indicator)

All thresholds are constants at the top of this file so they can be tuned
without touching logic.
"""
from __future__ import annotations

from typing import Any

from .vendor_lookup import lookup_vendor_safe, is_camera_like, is_camera_vendor

# ── Thresholds ───────────────────────────────────────────────────────

SUSPICIOUS_THRESHOLD = 3          # total score to flag a client
RECENT_SECONDS = 600              # "just appeared" = < 10 minutes ago
HIGH_BANDWIDTH_BYTES = 500_000_000  # 500 MB in a single session
SHORT_UPTIME_SECONDS = 120        # connected < 2 minutes
WEAK_SIGNAL_DBM = -80             # very weak RSSI
GUEST_HIGH_TRAFFIC_BYTES = 100_000_000  # 100 MB on guest network


def _is_locally_administered(mac: str) -> bool:
    """Return True if the MAC has the locally-administered bit set.

    This is the primary indicator of a randomized / privacy MAC address
    (iOS 14+, Android 10+, Windows 11).  The second hex digit of the
    first octet will be one of {2, 3, 6, 7, A, B, E, F}.
    """
    try:
        first_octet = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def analyze_client(
    client: dict[str, Any],
    *,
    now_ts: float,
    store_state: str = "new",
) -> dict[str, Any]:
    """Return a suspicion report for a single client.

    Returns a dict with:
        score       int   – cumulative suspicion score
        suspicious  bool  – score >= threshold
        flags       list  – human-readable reasons
        threat_level str  – "none" | "low" | "medium" | "high"
    """
    mac = client.get("mac", "")
    hostname = client.get("hostname") or client.get("name") or ""
    vendor = client.get("oui") or lookup_vendor_safe(mac)
    tx = client.get("tx_bytes") or 0
    rx = client.get("rx_bytes") or 0
    total_bytes = tx + rx
    uptime = client.get("uptime") or 0
    rssi = client.get("rssi")
    first_seen = client.get("first_seen")
    blocked = client.get("blocked", False)
    network = client.get("network") or client.get("essid") or ""
    is_guest = "guest" in network.lower()

    score = 0
    flags: list[str] = []

    # 1. Randomized MAC
    randomized = _is_locally_administered(mac)
    if randomized:
        score += 2
        flags.append("Randomized/private MAC address")

    # 2. Unknown vendor
    unknown_vendor = vendor in ("Unknown", "")
    if unknown_vendor:
        score += 1
        flags.append("Unknown vendor (not in OUI table)")

    # 3. No hostname
    if not hostname.strip():
        score += 1
        flags.append("No hostname reported")

    # 4. Very recently appeared
    if first_seen and isinstance(first_seen, (int, float)):
        age = now_ts - first_seen
        if 0 < age < RECENT_SECONDS:
            score += 2
            flags.append(f"Just appeared ({int(age)}s ago)")

    # 5. Very high bandwidth
    if total_bytes > HIGH_BANDWIDTH_BYTES:
        mb = total_bytes / 1_000_000
        score += 2
        flags.append(f"High bandwidth ({mb:.0f} MB this session)")

    # 6. Very short uptime (probe / drive-by)
    if 0 < uptime < SHORT_UPTIME_SECONDS:
        score += 1
        flags.append(f"Very short uptime ({uptime}s)")

    # 7. Weak signal
    if rssi is not None and rssi < WEAK_SIGNAL_DBM:
        score += 1
        flags.append(f"Weak signal ({rssi} dBm)")

    # 8. Previously blocked
    if blocked:
        score += 2
        flags.append("Currently blocked on controller")

    # 9. Guest network + high traffic
    if is_guest and total_bytes > GUEST_HIGH_TRAFFIC_BYTES:
        mb = total_bytes / 1_000_000
        score += 2
        flags.append(f"Guest network with high traffic ({mb:.0f} MB)")

    # 10. Randomized MAC + unknown vendor combo
    if randomized and unknown_vendor:
        score += 1
        flags.append("Randomized MAC with unknown vendor (strong indicator)")

    # 11. Camera vendor detected (Hikvision, Dahua, XMEye, etc.)
    camera = is_camera_like(mac, hostname, vendor)
    if camera and store_state == "new":
        score += 3
        if is_camera_vendor(vendor):
            flags.append(f"Camera vendor detected: {vendor}")
        else:
            flags.append("Hostname matches camera pattern")

    # 12. Camera with high bandwidth = likely streaming / phoning home
    if camera and total_bytes > 50_000_000:  # 50 MB
        mb = total_bytes / 1_000_000
        score += 2
        flags.append(f"Camera with high outbound traffic ({mb:.0f} MB)")

    # 13. Camera on non-isolated network (not on IoT/camera VLAN)
    if camera and not is_guest:
        net_lower = network.lower()
        if "iot" not in net_lower and "camera" not in net_lower and "isolated" not in net_lower:
            score += 1
            flags.append("Camera on main network (not isolated to IoT/camera VLAN)")

    # Determine threat level
    if score >= 6:
        threat_level = "high"
    elif score >= SUSPICIOUS_THRESHOLD:
        threat_level = "medium"
    elif score >= 1:
        threat_level = "low"
    else:
        threat_level = "none"

    return {
        "score": score,
        "suspicious": score >= SUSPICIOUS_THRESHOLD,
        "threat_level": threat_level,
        "flags": flags,
    }


def analyze_all_clients(
    clients: list[dict[str, Any]],
    *,
    now_ts: float,
    store_get_state: Any = None,
) -> dict[str, dict[str, Any]]:
    """Analyze all clients and return a dict keyed by MAC.

    *store_get_state* should be a callable(mac) -> state string, or None.
    """
    results: dict[str, dict[str, Any]] = {}
    for client in clients:
        mac = client.get("mac", "").lower()
        if not mac:
            continue
        state = store_get_state(mac) if store_get_state else "new"
        results[mac] = analyze_client(client, now_ts=now_ts, store_state=state)
    return results
