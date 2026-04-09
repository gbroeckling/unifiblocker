# Installation & UCG Max Setup Guide

## Prerequisites

- Home Assistant 2024.1.0 or later
- A UniFi OS controller (UCG Max, UDM, UDM Pro, UDM SE, or Cloud Key Gen2+)
- A **local admin account** on the controller (see below)
- Network access from HA to the controller on TCP port 443

## Step 1 — Create a Local Admin Account on the UCG Max

UniFi Blocker talks directly to the controller's local HTTPS API. **Cloud-only
(Ubiquiti SSO) accounts will not work.**  You must have a local admin:

1. Open your UniFi OS console in a browser: `https://192.168.1.1` (or your
   controller's IP)
2. Navigate to **OS Settings → Admins & Users**
3. Click **Add Admin**
4. Select **"Local Access Only"**
5. Set a username (e.g. `ha-unifiblocker`) and a strong password
6. Set the role to **Administrator**
   - This role is required for block/unblock commands
   - A read-only role will work for monitoring but cannot quarantine devices
7. Save the new admin

> **Tip:** Use a dedicated account for this integration so you can rotate
> credentials independently and audit API access in the controller logs.

## Step 2 — Find Your Controller IP

Your UCG Max is usually at `192.168.1.1`.  To confirm:

- In the UniFi console: **Settings → System → General** shows the management IP
- Or check your router/DHCP server for the UCG Max's address
- The UCG Max always serves HTTPS on port 443

If your HA instance and UCG Max are on different VLANs, make sure a firewall
rule allows HA → UCG Max on TCP 443.

## Step 3 — Install UniFi Blocker

### Option A: HACS (recommended)

1. Open HACS → Integrations → ⋮ menu → **Custom repositories**
2. URL: `https://github.com/gbroeckling/unifiblocker`
3. Category: **Integration**
4. Click **Add**, then find and install **UniFi Blocker**
5. Restart Home Assistant

### Option B: Manual

1. Download or clone this repository
2. Copy the `custom_components/unifiblocker/` folder into your HA
   `config/custom_components/` directory
3. Restart Home Assistant

## Step 4 — Add the Integration

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **UniFi Blocker**
3. Fill in the form:

| Field | Value | Notes |
|-------|-------|-------|
| **Host** | `192.168.1.1` | IP or hostname of your UCG Max |
| **Username** | `ha-unifiblocker` | The local admin you created |
| **Password** | *(your password)* | Stored encrypted in HA's config store |
| **Site** | `default` | Only change if you renamed your site |
| **Verify SSL** | Off | UCG Max uses a self-signed cert by default |
| **Scan interval** | `60` | Seconds between polls (lower = more responsive) |

4. Click **Submit** — the integration tests the connection before saving
5. If successful, sensors and services appear immediately

## Step 5 — Import the Dashboard (optional)

A ready-made Lovelace dashboard is included at `dashboards/unifiblocker_dashboard.yaml`:

1. Go to **Settings → Dashboards → Add Dashboard**
2. Choose a name (e.g. "UniFi Blocker")
3. In the new dashboard, click ⋮ → **Raw configuration editor**
4. Paste the contents of `unifiblocker_dashboard.yaml`
5. Save

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `cannot_connect` error | Verify the IP is correct and HA can reach port 443. Try `curl -k https://192.168.1.1/api/auth/login` from the HA host. |
| `invalid_auth` error | Make sure the account is **local** (not SSO/cloud). Check that the password is correct. The account must be an **Administrator** role. |
| Connection works but no clients shown | Check that the site name matches (usually `default`). |
| SSL certificate errors | Leave **Verify SSL** off — the UCG Max ships with a self-signed cert. |
| Block/unblock fails | The account must be an **Administrator** role, not a limited/read-only role. |
| HA and UCG Max on different VLANs | Add a firewall rule allowing HA's IP to reach the controller on TCP 443. |
| "Session expired" in logs | Normal — the integration automatically re-authenticates when the session cookie expires. |

## URL Formats Accepted

The integration accepts any of these host formats:

- `192.168.1.1`
- `192.168.1.1:443`
- `https://192.168.1.1`
- `https://192.168.1.1:443`
- `unifi.local`

It always uses HTTPS and strips any trailing paths.

## Security Notes

- Controller credentials are stored in HA's encrypted config entry store
- All API traffic uses HTTPS (TLS)
- Service calls require HA authentication
- The integration never sends data to external services
