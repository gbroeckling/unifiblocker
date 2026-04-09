# UniFi Blocker

**Network device review & quarantine for Home Assistant**

UniFi Blocker is a Home Assistant custom integration that connects directly to your **UniFi OS controller** (UCG Max, UDM, UDM Pro, etc.) to surface new clients, maintain a review queue, and let you trust, ignore, or quarantine devices — all from within Home Assistant.

## Features

- **Direct UniFi OS API communication** — authenticates to your UCG Max over HTTPS, polls active clients, and issues block/unblock commands in real time
- **Automatic new-device detection** — every unknown MAC that appears is flagged for review
- **MAC vendor lookup** — built-in OUI table covering 200+ common vendors (Apple, Samsung, Google, Amazon, Espressif, Ubiquiti, etc.)
- **Persistent device store** — classifications survive HA restarts
- **Security states** — mark devices as Trusted, Ignored, or Quarantined
- **Quarantine = block** — quarantining a device immediately blocks it on the controller
- **Rich sensors** — connected clients, new devices, blocked count, quarantined count, wireless/wired breakdown, trusted count
- **Binary sensor** — fires when unreviewed devices are on the network
- **Full client detail attributes** — every sensor exposes MAC, name, vendor, IP, SSID, RSSI, wired/wireless, traffic, uptime
- **Six service calls** — `trust_device`, `ignore_device`, `quarantine_device`, `block_device`, `unblock_device`, `reconnect_device`
- **Included Lovelace dashboard** — ready-made YAML with overview, new device review queue, all-client table, quarantine view, and actions reference

## Installation

### HACS (recommended)

1. Open HACS → Integrations → three-dot menu → **Custom repositories**
2. URL: `https://github.com/gbroeckling/unifiblocker`
3. Category: **Integration**
4. Click **Add**, then install **UniFi Blocker**
5. Restart Home Assistant

### Manual

Copy `custom_components/unifiblocker/` into your HA `config/custom_components/` directory and restart.

## Configuration

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **UniFi Blocker**
3. Enter your UCG Max details:
   - **Host** — IP or hostname of the controller (e.g. `192.168.1.1`)
   - **Username** — a local admin account on the controller
   - **Password**
   - **Site** — usually `default`
   - **Verify SSL** — leave off for self-signed certs (typical)
   - **Scan interval** — how often to poll (seconds, default 60)
4. The integration tests the connection before saving

## Dashboard

A complete Lovelace dashboard is included at `dashboards/unifiblocker_dashboard.yaml`.  Import it via **Settings → Dashboards → Add Dashboard** (YAML mode) or paste into any dashboard's raw config editor.

### Views

| View | What it shows |
|------|--------------|
| **Network Overview** | Client counts, security state counters, history graphs |
| **New Devices** | Full table of unreviewed devices with MAC, name, vendor, IP, SSID, RSSI |
| **All Clients** | Every connected client with complete detail |
| **Quarantined** | Blocked/quarantined devices with release instructions |
| **Actions** | Quick reference for all service calls |

## Services

| Service | Description |
|---------|------------|
| `unifiblocker.trust_device` | Mark as trusted; unblocks if blocked |
| `unifiblocker.ignore_device` | Remove from review queue |
| `unifiblocker.quarantine_device` | Mark quarantined + block on controller |
| `unifiblocker.block_device` | Immediately block on controller |
| `unifiblocker.unblock_device` | Remove block on controller |
| `unifiblocker.reconnect_device` | Force client reconnect (kick) |

All services take a single field: `mac` (e.g. `"aa:bb:cc:dd:ee:ff"`).

## Sensors

| Entity | Type | Description |
|--------|------|-------------|
| `sensor.unifiblocker_connected_clients` | Sensor | Total connected clients |
| `sensor.unifiblocker_new_devices` | Sensor | Unreviewed device count (attributes: full device list) |
| `sensor.unifiblocker_blocked_devices` | Sensor | Currently blocked on controller |
| `sensor.unifiblocker_quarantined_devices` | Sensor | Quarantined in local store |
| `sensor.unifiblocker_trusted_devices` | Sensor | Trusted device count |
| `sensor.unifiblocker_wireless_clients` | Sensor | Wi-Fi clients |
| `sensor.unifiblocker_wired_clients` | Sensor | Wired clients |
| `sensor.unifiblocker_all_clients_detail` | Sensor | Total count; `clients` attribute has full enriched table |
| `binary_sensor.unifiblocker_devices_pending_review` | Binary | ON when new devices exist |

## How it works

```
UCG Max (UniFi OS)                Home Assistant
┌──────────────┐   HTTPS/JSON    ┌──────────────────────┐
│  /api/auth   │◄───────────────►│  unifi_api.py        │
│  /stat/sta   │                 │  coordinator.py      │
│  /cmd/stamgr │                 │  device_store.py     │
│  /stat/device│                 │  sensor.py           │
│  /stat/sysinfo│                │  binary_sensor.py    │
└──────────────┘                 │  vendor_lookup.py    │
                                 └──────────────────────┘
```

1. **Login** — `POST /api/auth/login` with your credentials; session cookies + CSRF token stored
2. **Poll** — `GET /proxy/network/api/s/{site}/stat/sta` returns all connected clients
3. **Classify** — new MACs get state `new`; you classify via services
4. **Enforce** — quarantine/block calls `POST /cmd/stamgr` with `block-sta` or `unblock-sta`
5. **Enrich** — each client is annotated with vendor from the OUI table

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
