# UniFi Blocker

**Network device security for Home Assistant — see everything, control everything.**

UniFi Blocker is a Home Assistant custom integration that connects to your UniFi OS controller (UCG Max, UDM, UDM Pro, etc.) to give you complete visibility into every device on your network. It identifies, categorizes, and helps you isolate IoT devices — especially cheap IP cameras that phone home to cloud servers you don't control.

If you have Hikvision, Dahua, XMEye, or other budget cameras on your network, those devices are almost certainly calling home to Chinese cloud servers, often through undocumented backdoor ports. UniFi Blocker finds them, tells you exactly what they are doing, and gives you the tools to shut it down — all from a sidebar panel inside Home Assistant.

---

## Screenshots

| Sidebar Panel | Device Detail | Security Dashboard |
|:---:|:---:|:---:|
| ![Sidebar Panel](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/panel-overview.png) | ![Device Detail](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/device-detail.png) | ![Security Dashboard](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/security-dashboard.png) |

| Port Scan Results | ONVIF Discovery | Suspicious Traffic |
|:---:|:---:|:---:|
| ![Port Scan](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/port-scan.png) | ![ONVIF](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/onvif-discovery.png) | ![Suspicious](https://raw.githubusercontent.com/gbroeckling/unifiblocker/main/screenshots/suspicious-traffic.png) |

---

## Features

### Sidebar Panel
A dedicated sidebar panel in Home Assistant gives you a single-pane view of your entire network. The panel opens in **read-only mode** by default — you can browse, scan, and review without risk. Toggle **Action Mode** to make changes like blocking devices, changing categories, or assigning local-only IPs.

### Device Categorization
Every device on your network is automatically classified into one of 16 categories:

| Category | Description | Category | Description |
|----------|-------------|----------|-------------|
| Camera | IP cameras, DVRs, NVRs | Smart Speaker | Echo, Nest, HomePod |
| Computer | Desktops, laptops | Streaming | Roku, Chromecast, Fire TV |
| Phone | Smartphones | Gaming | Consoles, gaming PCs |
| Tablet | Tablets, iPads | Printer | Printers, scanners |
| ESPHome | ESP32/ESP8266 devices | Networking | Routers, switches, APs |
| Smart Light | WLED, Govee, Hue | Crypto | Miners, ASIC devices |
| HA Device | Home Assistant instances | IoT | Generic smart home |
| NAS | Synology, QNAP, TrueNAS | Unknown | Unidentified devices |

Classification uses a 10-level priority system: manual override, ONVIF probe, port scan results, vendor OUI, chip vendor analysis, hostname patterns, vendor mapping, DPI traffic, learned patterns, and finally unknown.

### Learning Engine
When you manually categorize a device, UniFi Blocker learns from it. It extracts the vendor string, hostname prefix, MAC prefix, and open port signature, then automatically applies those patterns to other uncategorized devices. Categorize one Hikvision camera and every other Hikvision on your network gets tagged automatically.

### Port Scanner
A targeted TCP connect scanner checks approximately 120 ports on each device, focused on the ports that actually matter for device identification and security. Not a general-purpose Nmap clone — this scanner knows what camera ports look like:

- **Camera protocols** — RTSP (554), RTMP (1935), ONVIF (3702, 8899)
- **Vendor-specific** — Hikvision SDK (8000, 9527), Dahua (37777, 37778), XMEye (34567, 34568), Reolink (9000, 32100)
- **Cloud/P2P relay** — ports cameras use to phone home (6789, 19000, 15000, 20000)
- **Backdoors** — Dahua debug port (9530), insecure Telnet (23, 2323)
- **Everything else** — SSH, HTTP, SMB, MQTT, ESPHome, Plex, crypto mining, and more

Scan results are cached and persist across Home Assistant restarts. A 5-minute cooldown prevents rescanning the same device.

### ONVIF Discovery
Uses the ONVIF protocol to definitively identify cameras. Instead of guessing from MAC addresses, it asks each device directly: "What are you?" Returns the exact manufacturer, model, firmware version, and serial number. This is how professional NVR software discovers cameras — no guesswork involved.

### Suspicious Traffic Analysis
A 13-point heuristic scoring system flags devices that warrant review:

- Randomized/locally-administered MAC address
- Unknown vendor (not in OUI table)
- No hostname reported
- First seen very recently (probe behavior)
- Extremely high bandwidth usage
- Very short uptime (hit-and-run connection)
- Anomalous wireless signal strength
- Previously blocked on the controller
- Guest network with high traffic (data exfiltration pattern)
- Known camera vendor with internet access
- And more

Devices scoring above the threshold are flagged for your attention.

### Camera Vendor Detection
Identifies 50+ camera manufacturers including Hikvision, Dahua, XMEye/Xiongmai, Reolink, EZVIZ, Imou, Amcrest, Foscam, Annke, Lorex, Swann, Axis, Vivotek, Uniview, and many others. Also detects camera chip vendors (HiSilicon, Ingenic) that appear in generic/white-label cameras.

### Local-Only Network Management
Assign devices to your local-only subnet (192.168.2.x) directly from the panel. Devices on this range work locally (RTSP streaming, ONVIF, NVR recording) but cannot reach the internet. IP addresses are automatically grouped by device category:

| Range | Category | Range | Category |
|-------|----------|-------|----------|
| .30-.50 | Cameras | .121-.130 | Streaming |
| .51-.70 | ESPHome | .131-.140 | Printers |
| .71-.90 | Smart Lights | .141-.150 | Gaming |
| .91-.100 | Smart Speakers | .151-.160 | Crypto |
| .101-.120 | IoT | .161-.170 | NAS |

### Per-Port Firewall Rules
Block specific ports on specific devices without fully isolating them. If a camera needs local RTSP access but you want to block its cloud relay ports, you can do exactly that.

### Security Recommendations
Generates prioritized, actionable security advice for every device based on vendor, category, open ports, and network placement. Includes CVE references for known-vulnerable vendors:

- **Hikvision** — CVE-2021-36260 (RCE), CVE-2017-7921 (auth bypass), CVE-2023-6895
- **Dahua** — CVE-2021-33044, CVE-2021-33045 (auth bypass)
- **XMEye/Xiongmai** — CVE-2018-10088 (buffer overflow RCE), primary Mirai botnet target

### Additional Features
- **Network Access Security dashboard** — overview of your network's security posture
- **Port reference guide** — explains what each camera phone-home port does
- **Persistent configuration** — device store, scan cache, and learned patterns survive restarts and reinstalls
- **Rich sensors** — connected clients, new devices, blocked count, wireless/wired breakdown
- **Binary sensor** — fires when unreviewed devices appear on the network
- **Six service calls** — trust, ignore, quarantine, block, unblock, reconnect

---

## Installation

### HACS (Recommended)

1. Open **HACS** in Home Assistant
2. Go to **Integrations** and click the three-dot menu
3. Select **Custom repositories**
4. Enter URL: `https://github.com/gbroeckling/unifiblocker`
5. Category: **Integration**
6. Click **Add**, then find and install **UniFi Blocker**
7. **Restart Home Assistant**

### Manual

Copy `custom_components/unifiblocker/` into your Home Assistant `config/custom_components/` directory and restart.

---

## Setup

1. Go to **Settings > Devices & Services > Add Integration**
2. Search for **UniFi Blocker**
3. Enter your UniFi controller details:
   - **Host** — IP of your UCG Max / UDM (e.g., `192.168.1.1`)
   - **Username** — a local admin account on the controller
   - **Password**
   - **Site** — usually `default`
   - **Verify SSL** — leave off for self-signed certificates (typical)
   - **Scan interval** — polling frequency in seconds (default: 60)
4. The integration tests the connection before saving. Once connected, the **UniFi Blocker** sidebar panel appears automatically.

---

## Using the Sidebar Panel

The sidebar panel is your primary interface. Click the shield icon in the Home Assistant sidebar to open it.

### Read-Only Mode (Default)
When you first open the panel, it is in read-only mode. You can:
- Browse all connected devices
- View device details (MAC, IP, vendor, hostname, category, open ports)
- See security recommendations and suspicious traffic scores
- Review ONVIF discovery results
- Check the Network Access Security dashboard

### Action Mode
Toggle **Action Mode** at the top of the panel to enable changes:
- Categorize devices manually
- Assign devices to the local-only subnet (192.168.2.x)
- Block or quarantine devices
- Create per-port firewall rules
- Trust or ignore devices

Action Mode exists to prevent accidental changes. Browse freely in read-only mode; switch to Action Mode only when you need to make changes.

---

## Recommended Workflow

1. **Install and connect** — add the integration, point it at your UCG Max
2. **Review the dashboard** — open the sidebar panel and browse your devices
3. **Run port scans** — scan unknown devices to fingerprint them
4. **Check ONVIF** — let ONVIF discovery identify your cameras definitively
5. **Categorize** — manually categorize a few devices; the learning engine handles the rest
6. **Isolate cameras** — move cameras and risky IoT to 192.168.2.x (local-only, no internet)
7. **Monitor** — check the suspicious traffic analysis periodically for anomalies

---

## Network Setup

UniFi Blocker works best with a flat /22 network that uses IP-range-based firewall rules instead of VLANs. This gives you camera isolation with zero VLAN complexity.

**See [NETWORK_GUIDE.md](NETWORK_GUIDE.md) for the complete step-by-step network setup guide**, including:
- Why cheap cameras are dangerous
- How to configure the /22 subnet on your UCG Max
- DHCP and firewall rule setup
- The recommended camera isolation workflow

---

## Sensors

| Entity | Type | Description |
|--------|------|-------------|
| `sensor.unifiblocker_connected_clients` | Sensor | Total connected clients |
| `sensor.unifiblocker_new_devices` | Sensor | Unreviewed device count |
| `sensor.unifiblocker_blocked_devices` | Sensor | Currently blocked on controller |
| `sensor.unifiblocker_quarantined_devices` | Sensor | Quarantined in local store |
| `sensor.unifiblocker_trusted_devices` | Sensor | Trusted device count |
| `sensor.unifiblocker_wireless_clients` | Sensor | Wi-Fi clients |
| `sensor.unifiblocker_wired_clients` | Sensor | Wired clients |
| `sensor.unifiblocker_all_clients_detail` | Sensor | Total count with full client detail in attributes |
| `binary_sensor.unifiblocker_devices_pending_review` | Binary | ON when unreviewed devices exist |

## Services

| Service | Description |
|---------|-------------|
| `unifiblocker.trust_device` | Mark as trusted; unblocks if blocked |
| `unifiblocker.ignore_device` | Remove from review queue |
| `unifiblocker.quarantine_device` | Mark quarantined and block on controller |
| `unifiblocker.block_device` | Immediately block on controller |
| `unifiblocker.unblock_device` | Remove block on controller |
| `unifiblocker.reconnect_device` | Force client reconnect (kick) |

All services accept a single parameter: `mac` (e.g., `"aa:bb:cc:dd:ee:ff"`).

---

## How It Works

```
UCG Max (UniFi OS)                Home Assistant
+------------------+  HTTPS/JSON  +------------------------+
|  /api/auth/login |<------------>|  unifi_api.py          |
|  /stat/sta       |              |  coordinator.py        |
|  /cmd/stamgr     |              |  device_store.py       |
|  /stat/device    |              |  device_categorizer.py |
|  /rest/firewallrule|            |  port_scanner.py       |
|  /rest/user      |              |  onvif_probe.py        |
|  /stat/stadpi    |              |  suspicious_traffic.py |
+------------------+              |  learning.py           |
                                  |  local_network.py      |
                                  |  recommendations.py    |
                                  |  panel.py (sidebar)    |
                                  +------------------------+
```

1. **Login** — authenticates to UniFi OS via `/api/auth/login`; session cookies and CSRF token stored
2. **Poll** — fetches all connected clients, DPI data, device info, and firewall rules
3. **Categorize** — every client is classified using the 10-level priority system
4. **Scan** — on-demand port scanning and ONVIF discovery fingerprint devices
5. **Analyze** — suspicious traffic heuristics score each device
6. **Recommend** — security engine generates advice based on vendor, ports, and placement
7. **Enforce** — block/unblock commands and firewall rules pushed back to the controller

---

## Requirements

- Home Assistant 2024.1.0 or later
- UniFi OS controller (UCG Max, UDM, UDM Pro, UDM SE, or similar)
- A local admin account on the controller
- Network access from Home Assistant to the controller over HTTPS

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
