# Network Guide — Flat /22 Camera Isolation

This guide explains how to set up a flat /22 network on a UniFi UCG Max to isolate IP cameras and IoT devices from the internet without using VLANs. This is the network architecture that UniFi Blocker is designed to manage.

---

## Table of Contents

- [Why Cheap Cameras Are Dangerous](#why-cheap-cameras-are-dangerous)
- [Why a Flat /22 Instead of VLANs](#why-a-flat-22-instead-of-vlans)
- [Network Architecture Overview](#network-architecture-overview)
- [Step-by-Step UCG Max Setup](#step-by-step-ucg-max-setup)
  - [1. Change the LAN Subnet to /22](#1-change-the-lan-subnet-to-22)
  - [2. Configure the DHCP Pool](#2-configure-the-dhcp-pool)
  - [3. Create DHCP Reservations](#3-create-dhcp-reservations)
  - [4. Create the Firewall Rule](#4-create-the-firewall-rule)
- [How UniFi Blocker Automates This](#how-unifi-blocker-automates-this)
- [Recommended Camera Workflow](#recommended-camera-workflow)
- [FAQ and Troubleshooting](#faq-and-troubleshooting)

---

## Why Cheap Cameras Are Dangerous

Budget IP cameras from brands like Hikvision, Dahua, XMEye/Xiongmai, and their consumer sub-brands (EZVIZ, Imou, Hiseeu, Zosi, Annke) are among the most dangerous devices you can put on a home network. Here is why.

### They Phone Home Constantly

These cameras establish persistent outbound connections to cloud servers — typically in China — even when you have not configured any cloud features. Common destinations include:

- **Hikvision** — dev.hikvision.com, hik-connect.com, ezvizlife.com
- **Dahua** — easy4ip.com, cloud-service.dahuatech.com, imoulife.com
- **XMEye** — xmeye.net, xmcsrv.net, nseye.com, eseecloud.com

These connections use proprietary protocols on non-standard ports (34567, 37777, 6789, 8800, 19000, 32100, and others) that are difficult to monitor and impossible to audit. The cameras are sending data to servers you do not control, and you have no way to verify what is being transmitted.

### They Have Critical Vulnerabilities

The security track record of these vendors is severe:

| Vendor | CVEs | Impact |
|--------|------|--------|
| **Hikvision** | CVE-2021-36260 | Remote code execution — full device takeover with a single HTTP request. No authentication required. CVSS 9.8. |
| **Hikvision** | CVE-2017-7921 | Authentication bypass — access any camera's live feed without a password. |
| **Hikvision** | CVE-2023-6895 | Command injection via web interface. |
| **Dahua** | CVE-2021-33044, CVE-2021-33045 | Authentication bypass — two separate vulnerabilities allowing unauthenticated access. |
| **XMEye/Xiongmai** | CVE-2018-10088 | Buffer overflow leading to remote code execution. |

These are not theoretical risks. They were actively exploited at scale.

### They Were the Mirai Botnet

In 2016, the Mirai botnet took down major internet infrastructure (DNS provider Dyn, causing outages at Twitter, Netflix, Reddit, and others). The botnet was built primarily from compromised Xiongmai/XMEye cameras and DVRs. These devices had hardcoded credentials that could not be changed, Telnet enabled by default, and firmware update mechanisms controlled entirely by the cloud.

**XMEye devices remain the highest-risk IoT devices you can own.** Their cloud account system cannot be fully disabled. The firmware can be updated remotely by the vendor without your consent. If one is on your network with internet access, assume it is compromised or will be.

### Disabling Cloud Is Not Enough

Even when you disable P2P, cloud, and remote access in the camera settings:
- Many cameras continue to resolve and contact cloud DNS servers
- Some maintain persistent connections on non-standard ports
- Firmware updates can re-enable features you turned off
- Backdoor ports (like Dahua's port 9530) exist independently of any settings

**The only reliable solution is to prevent the device from reaching the internet at the network level.** That is what this guide sets up.

---

## Why a Flat /22 Instead of VLANs

The standard advice for IoT isolation is "put them on a separate VLAN." That works, but it introduces complexity that most home users do not need:

| Concern | VLANs | Flat /22 |
|---------|-------|----------|
| **Setup complexity** | Create VLAN, SSID, assign ports, configure inter-VLAN routing and firewall rules | Change subnet mask from /24 to /22, add one firewall rule |
| **Moving a device** | Reassign to a different VLAN/SSID, possibly change switch port config | Change the DHCP reservation IP address |
| **Multicast/mDNS** | Requires mDNS reflector or Avahi across VLANs for device discovery | Works natively — same broadcast domain |
| **RTSP streaming** | Must configure firewall rules to allow NVR/Frigate to reach camera VLAN | Works natively — all devices can reach each other on the LAN |
| **Complexity over time** | Grows with every new VLAN, SSID, and firewall rule | Stays the same regardless of device count |

A flat /22 network keeps everything in a single broadcast domain. Isolation is achieved through IP-range-based firewall rules rather than network segmentation. The result is functionally equivalent for home use: cameras on 192.168.2.x can stream to your NVR but cannot reach the internet.

### Trade-offs

A flat network does have limitations compared to VLANs:

- Devices on 192.168.2.x can still reach devices on 192.168.1.x at the LAN level (ARP, broadcast). This is fine for cameras streaming to a local NVR, but it means a compromised camera could potentially scan your trusted devices. For most home networks, this is an acceptable trade-off.
- True VLANs provide Layer 2 isolation that a flat network cannot. If you are running a business or have regulatory requirements, use VLANs.
- This approach relies on the UCG Max firewall to block WAN access. If the firewall rule is misconfigured or deleted, 192.168.2.x devices regain internet access.

For the vast majority of home users, the simplicity of a flat /22 far outweighs these concerns.

---

## Network Architecture Overview

```
              Internet
                 |
          +------+------+
          |   UCG Max   |
          |  Gateway    |
          | 192.168.1.1 |
          +------+------+
                 |
     Single LAN — 192.168.0.0/22  (255.255.252.0)
     Usable range: 192.168.0.1 — 192.168.3.254
                 |
    +------------+------------+------------------+
    |            |            |                  |
 Trusted     Local-Only    DHCP Pool         Reserved
 192.168.1.x 192.168.2.x  192.168.3.x       192.168.0.x
    |            |            |
 Full access  NO internet  Full access
 Static IPs   Static IPs   Dynamic IPs
 (reserved)   (reserved)   (auto-assigned)
```

### The Three Ranges

| Range | Purpose | Internet | IP Assignment | Example Devices |
|-------|---------|----------|---------------|-----------------|
| **192.168.1.x** | Trusted devices | Full access | DHCP reservations (static) | PCs, phones, tablets, Home Assistant, NVR |
| **192.168.2.x** | Local-only devices | Blocked by firewall | DHCP reservations (static) | IP cameras, IoT that should not phone home |
| **192.168.3.x** | Default DHCP pool | Full access | Dynamic (auto) | New devices land here for review |

This is still one flat network. Every device can talk to every other device on the LAN. The only difference is that 192.168.2.x devices are blocked from reaching the WAN (internet) by a single firewall rule on the UCG Max.

### How Moving a Device Works

Want to move a camera from "internet access" to "local-only"?

1. Find its MAC address (UniFi Blocker shows this)
2. Create or change its DHCP reservation from 192.168.1.x or 192.168.3.x to 192.168.2.x
3. Reconnect the device (or wait for DHCP lease renewal)

That is it. No VLAN reassignment, no SSID change, no switch port reconfiguration. The firewall rule already blocks all of 192.168.2.0/24 from reaching WAN.

---

## Step-by-Step UCG Max Setup

### 1. Change the LAN Subnet to /22

By default, UniFi creates a 192.168.1.0/24 network. You need to expand it to /22.

1. Open the UniFi controller at `https://192.168.1.1`
2. Go to **Settings > Networks**
3. Click on your **Default** network (or your LAN network)
4. Under **Host Address**, keep `192.168.1.1`
5. Change **Subnet Mask** to `255.255.252.0` (this is a /22)
6. This gives you the range 192.168.0.1 through 192.168.3.254 — 1,022 usable addresses
7. Click **Save**

> **Warning:** Changing the subnet mask will briefly disconnect clients as they renew their DHCP leases. Do this during a maintenance window or when disruption is acceptable.

After saving, your UCG Max now treats 192.168.0.0 through 192.168.3.255 as a single LAN. All three /24 ranges are part of the same broadcast domain.

### 2. Configure the DHCP Pool

Set the automatic DHCP pool to only hand out addresses in the 192.168.3.x range. This way, new devices that connect automatically get an IP in the "default pool" range where they have internet access and can be reviewed.

1. In the same network settings, find **DHCP Range**
2. Set the range to:
   - **Start:** `192.168.3.1`
   - **End:** `192.168.3.254`
3. Click **Save**

Now the DHCP server will only auto-assign addresses in 192.168.3.x. The 192.168.1.x and 192.168.2.x ranges are reserved for devices with explicit DHCP reservations (static IPs).

### 3. Create DHCP Reservations

For every device you want on a specific range, create a DHCP reservation (also called a fixed IP or static mapping).

#### For Trusted Devices (192.168.1.x)

1. Go to **Clients** in the UniFi controller
2. Click on a device (e.g., your desktop PC)
3. Under **Network**, click **Fixed IP Address**
4. Enter an IP in the 192.168.1.x range (e.g., `192.168.1.100`)
5. Click **Save**

Repeat for all trusted devices: your computers, phones, Home Assistant server, NVR, etc.

#### For Local-Only Devices (192.168.2.x)

Same process, but assign IPs in the 192.168.2.x range:

1. Click on a device (e.g., a Hikvision camera)
2. Set fixed IP to `192.168.2.30` (UniFi Blocker uses .30-.50 for cameras)
3. Click **Save**

The device will pick up its new IP on the next DHCP renewal. You can force this by reconnecting the device or using UniFi Blocker's reconnect service.

#### Suggested IP Layout for 192.168.2.x

UniFi Blocker automatically assigns IPs within these ranges when you move a device to local-only:

| Range | Category |
|-------|----------|
| .30 - .50 | Cameras |
| .51 - .70 | ESPHome devices |
| .71 - .90 | Smart lights |
| .91 - .100 | Smart speakers |
| .101 - .120 | Generic IoT |
| .121 - .130 | Streaming devices |
| .131 - .140 | Printers |
| .141 - .150 | Gaming |
| .151 - .160 | Crypto miners |
| .161 - .170 | NAS |
| .171 - .180 | Home Assistant devices |
| .181 - .190 | Networking equipment |
| .191 - .210 | Computers |
| .211 - .220 | Phones |
| .221 - .230 | Tablets |

Addresses .1-.5 and .255 are reserved and never auto-assigned.

### 4. Create the Firewall Rule

This is the single rule that makes the entire isolation scheme work. It blocks all outbound internet traffic from 192.168.2.0/24.

1. Go to **Settings > Firewall & Security > Firewall Rules**
2. Click **Create New Rule**
3. Configure:
   - **Name:** `Block Local-Only from WAN` (or any name you prefer)
   - **Type:** **Internet Out** (sometimes labeled "WAN Out" or "LAN Out to Internet")
   - **Action:** **Drop**
   - **Source:**
     - Type: **Network / IP Address**
     - Value: `192.168.2.0/24`
   - **Destination:** **Any**
   - **Protocol:** **All**
4. Make sure the rule is **enabled**
5. Click **Save**

> **What this does:** Any device with an IP in 192.168.2.0/24 can communicate freely on the local network (LAN) but all packets destined for the internet (WAN) are silently dropped. Your cameras can still stream via RTSP to your NVR or Frigate instance on 192.168.1.x, respond to ONVIF probes, and be managed locally. They just cannot phone home.

> **What this does NOT do:** This rule does not prevent devices on 192.168.2.x from communicating with devices on 192.168.1.x or 192.168.3.x at the LAN level. If you need to block inter-device communication as well, you would need additional firewall rules or VLANs — but for camera isolation, blocking WAN access is sufficient.

#### Optional: Allow DNS for Local-Only Devices

Some cameras will stall or show errors if they cannot resolve DNS at all. You can optionally allow DNS queries from 192.168.2.x to your local DNS server while still blocking everything else:

1. Create a new rule **above** the block rule (rules are evaluated top-down)
2. Configure:
   - **Name:** `Allow Local-Only DNS`
   - **Type:** **LAN In**
   - **Action:** **Accept**
   - **Source:** `192.168.2.0/24`
   - **Destination:** `192.168.1.1` (your gateway/DNS)
   - **Protocol:** **UDP**
   - **Port:** `53`
3. The device can resolve hostnames but all actual traffic to the internet is still dropped by the block rule

This is optional. Most cameras work fine without DNS when they already know your NVR's IP address.

---

## How UniFi Blocker Automates This

With the /22 network and firewall rule in place, UniFi Blocker handles the day-to-day workflow:

### Discovery
- Polls the UniFi controller for all connected clients
- New devices appear in the review queue automatically
- ONVIF discovery finds cameras without manual searching

### Identification
- Port scanner fingerprints each device (~120 ports, camera-focused)
- ONVIF probe gets exact manufacturer, model, and firmware
- Learning engine applies patterns from your previous categorizations
- Vendor OUI lookup identifies the manufacturer from the MAC address

### Assessment
- Suspicious traffic analysis scores each device on 13 heuristics
- Security recommendations surface CVEs and phone-home behavior
- Camera vendor detection flags known-risky manufacturers

### Isolation
- One-click assignment to 192.168.2.x from the sidebar panel
- Automatic IP selection within the correct category range
- DHCP reservation created via the UniFi API
- Device reconnect to pick up the new IP

### Ongoing Monitoring
- Continuous polling detects new devices as they appear
- Scan results persist across restarts
- Configuration survives reinstalls
- Dashboard shows your network's security posture at a glance

---

## Recommended Camera Workflow

When you discover a new camera on your network — or want to audit existing cameras — follow this workflow:

### 1. Discover

Open UniFi Blocker's sidebar panel and check the device list. New devices appear in the review queue. Cameras identified by ONVIF or vendor OUI are highlighted automatically.

### 2. Scan

Run a port scan on the device. The results tell you exactly what the camera is doing:

- **RTSP (554)** — streaming protocol. This is what your NVR uses. You want this.
- **HTTP/HTTPS (80, 443)** — web interface. Useful for configuration.
- **Hikvision SDK (8000)** — the iVMS-4200 management port. Local-only, fine to keep.
- **Dahua TCP (37777)** — Dahua's management protocol. Local-only, fine to keep.
- **Cloud/P2P ports (6789, 34567, 19000, 32100)** — these are the phone-home ports. These are what you want to block.
- **Dahua debug (9530)** — a known backdoor port. If this is open, isolate the device immediately.
- **Telnet (23)** — should never be open. If it is, the device is insecure.

### 3. Categorize

Set the device category to "camera" if it was not auto-detected. The learning engine will remember the pattern and apply it to similar devices in the future.

### 4. Check Security Recommendations

Review the security recommendations for the device. If it is a Hikvision, Dahua, or XMEye camera, the recommendations will include specific CVE references and isolation advice.

### 5. Isolate

From the sidebar panel (in Action Mode), assign the camera to the local-only subnet. UniFi Blocker will:

1. Pick an IP in the 192.168.2.30-.50 range (cameras)
2. Create a DHCP reservation via the UniFi API
3. Reconnect the device so it picks up the new IP
4. The existing firewall rule blocks all WAN traffic from 192.168.2.0/24

The camera continues to stream locally via RTSP to your NVR or Frigate. ONVIF discovery and management still work. The only difference is the camera can no longer reach the internet.

### 6. Verify

After isolation, run another port scan to confirm the device is working locally. Check that:
- RTSP (554) is still accessible from your NVR
- The camera appears in Frigate / Blue Iris / your NVR software
- Cloud/P2P ports are no longer reaching external servers (the firewall blocks this, but you can verify with the suspicious traffic analysis)

---

## FAQ and Troubleshooting

### General Questions

**Q: Will this break my cameras?**

No. IP cameras work entirely over local protocols (RTSP, ONVIF, HTTP). The cloud connectivity is used for remote viewing apps (Hik-Connect, DMSS, XMEye app). If you use those apps, you will lose remote access through the vendor's app. Use Home Assistant, Frigate, or a VPN for remote access instead — these are more secure alternatives.

**Q: Can I still update camera firmware after isolation?**

Not over the internet. Download firmware updates manually from the vendor's website and apply them through the camera's local web interface (HTTP on port 80 or 443). This is actually safer — it prevents the vendor from pushing unwanted firmware changes.

**Q: Do I need a UniFi switch or APs for this to work?**

You need a UniFi gateway (UCG Max, UDM, UDM Pro, etc.) running UniFi OS. The switches and APs can be any brand. The DHCP and firewall are handled by the gateway. UniFi Blocker communicates with the UniFi OS API on the gateway.

**Q: Can I use different IP ranges than 192.168.1-3.x?**

The /22 subnet starting at 192.168.0.0 gives you 192.168.0.x through 192.168.3.x. The choice of which /24 range is "trusted" vs "local-only" vs "DHCP pool" is enforced only by the firewall rule — you can rearrange them if you prefer. The defaults in UniFi Blocker (192.168.1.x trusted, 192.168.2.x local-only, 192.168.3.x DHCP) match common home network conventions.

**Q: I already have devices on 192.168.1.x with a /24 subnet. Will changing to /22 break anything?**

No. Expanding from /24 (255.255.255.0) to /22 (255.255.252.0) adds addresses — it does not remove any. All existing 192.168.1.x devices keep working. They will briefly reconnect as DHCP leases renew, but their reserved IPs do not change.

**Q: What about IPv6?**

This guide covers IPv4 only. If your cameras have IPv6 connectivity, they may be able to bypass the firewall rule. To be safe, disable IPv6 on your network or add an equivalent IPv6 firewall rule blocking the local-only range from WAN.

### Troubleshooting

**Camera is on 192.168.2.x but still appears to have internet access**

1. Verify the firewall rule exists and is enabled in **Settings > Firewall & Security > Firewall Rules**
2. Confirm the rule is type "Internet Out" (not "LAN In" or "LAN Local")
3. Check that the source is `192.168.2.0/24` and the action is "Drop"
4. Make sure no rule above it is allowing traffic from 192.168.2.0/24 to WAN
5. Reconnect the device to ensure it has picked up its 192.168.2.x IP (check in the UniFi client list)

**Camera is not accessible after moving to 192.168.2.x**

1. The device may not have renewed its DHCP lease yet. Use UniFi Blocker's reconnect service or power-cycle the camera.
2. Check the UniFi client list to confirm the camera's current IP is in the 192.168.2.x range.
3. Verify that your NVR / Frigate is configured to access the camera at the new IP address. If you used the old 192.168.1.x or 192.168.3.x address, you need to update the RTSP URL.

**ONVIF discovery is not finding my cameras**

1. ONVIF uses UDP multicast on port 3702. Some cameras have ONVIF disabled by default — enable it in the camera's web interface.
2. The Home Assistant host must be on the same broadcast domain as the cameras. In a flat /22 network, this is always the case.
3. Some very cheap cameras (sub-$20) do not support ONVIF at all.

**Port scan shows no open ports**

1. The device may be offline or unreachable. Check that it has an active IP in the UniFi client list.
2. The device may have a host firewall blocking port scans. Some enterprise cameras (Axis, Hanwha) are locked down by default.
3. Try pinging the device's IP from the Home Assistant host to confirm basic connectivity.

**New devices are not appearing in the review queue**

1. Check the polling interval in the integration settings. The default is 60 seconds — new devices appear within one polling cycle.
2. Verify the integration is running: check **Settings > Devices & Services** and look for UniFi Blocker. If it shows an error, check your credentials and network connectivity to the UCG Max.

**UniFi Blocker cannot connect to the controller**

1. Verify the UCG Max IP, username, and password in the integration settings.
2. The account must be a local admin account on the controller (not a Ubiquiti cloud account, unless the controller is set up for cloud access).
3. If using HTTPS with a self-signed certificate (the default), make sure "Verify SSL" is set to off in the integration settings.
4. Check that the Home Assistant host can reach the UCG Max on port 443.

---

## Further Reading

- [UniFi Blocker README](README.md) — full feature list and integration setup
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute to the project
- [CHANGELOG.md](CHANGELOG.md) — version history and release notes
