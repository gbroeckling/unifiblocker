# Changelog

## 0.3.61 (not released yet)

New panel, and blocking that does what it says.

- The panel is rebuilt (Lit + TypeScript, source in `frontend/`): Overview, Devices, Cameras, Home, Security, Network, Mining, Tools, with a device drawer, works in dark mode and on a phone.
- Block internet: one per-device rule, the address stays the same, so recorders keep working. Allow internet again undoes it. This is now the first action offered for cameras, including "Block internet for all" on the Cameras page.
- Containment is judged by real rules, not by the address: a device in the local-only range with no rule is reported as open, with a button to block it.
- Block the whole range (Network page): two gateway rules block a range such as 192.168.2.0/25 from the internet, time sync (NTP) still allowed. It only accepts ranges inside the local-only /24, warns about NAS and computers in the range, and refuses on controllers using the zone-based firewall. Off unless you turn it on.
- New per-device rules are named "UB: <mac> no internet". Older "local-only" ones still count.

## 0.3.60 — 2026-10-19

Home automation.

- Home automation devices are sorted by how much they depend on someone else's cloud: local (ESPHome, WLED, Tasmota, Zigbee coordinators, Vera), cloud with a local option (Tuya, Shelly, Kasa/Tapo, Govee, Xiaomi, Sonoff, Hue, IKEA, ecobee, Control4...), and cloud only (Echo, Google/Nest, Ring, Wyze, ChargePoint, robot vacuums).
- Cloud-tied devices are watched by the phone-home monitor too.
- Devices with a local option get a recommendation saying how to switch Home Assistant to it, and to do that before putting them on local-only, because cutting them off first breaks them.

## 0.3.59 — 2026-10-19

New-device policy.

- A camera seen for the first time is cut off from the internet straight away (`block_internet`, the default) with a per-device traffic rule. Its IP doesn't change, so local viewing and recording keep working. You get a notification, and trusting the camera removes the block. Set it to `notify` or `off` under Configure.
- Other new devices get one notification listing them (`notify`, the default, or `off`) and a `unifiblocker_new_device` event each.
- Nothing already on your network counts as new after you update, so you won't get a flood.

## 0.3.58 — 2026-10-19

Phone-home monitor.

- Cameras and every device on local-only, quarantined or blocked are checked against UniFi's traffic flows every 15 minutes. Device cards show what each one tries to reach (host, port, country), whose cloud it is (Xiongmai, Hikvision, Tuya, TP-Link...), and how many attempts were blocked by its local-only rule.
- Contained devices show "contained" when UniFi only logged blocked attempts, and "NOT contained" if it ever logs traffic it let through. That comes with a critical recommendation and a `unifiblocker_containment_failed` event.
- Flags devices probing for a way out (5+ different ports on one server, as P2P cameras do) and devices using their own DNS server instead of yours.
- UniFi only logs blocked traffic, so for a camera that isn't contained the card says what it reaches can't be seen until it's on local-only, instead of implying it's quiet.

## 0.3.57 — 2026-10-19

Using what current UniFi firmware actually reports.

- Security events come from UniFi's system log now. The old event feed is gone on UniFi Network 9/10, so the Threats page and sensor were always empty. Blocks made by UniFi Blocker's own local-only rules are counted separately and shown on each device as proof the rule is working, not as threats.
- Every device card shows its traffic for the last 24 hours, and a sudden spike (5x its usual hourly level, at least 50 MB) gets a recommendation, high for cameras.
- UniFi's own device fingerprint counts as camera evidence (medium confidence) and shows on device cards.
- Wi-Fi networks around you are checked for camera hotspots: one of your own cameras broadcasting its own network (a way in that skips your firewall) gets a high recommendation, and camera setup networks in range get a note.

## 0.3.56 — 2026-10-19

- The ONVIF probe followed redirects, so any web server that bounces /onvif/device_service to its login page (a UniFi NAS, for one) looked like an ONVIF camera. It doesn't follow redirects now, and only a real SOAP reply counts. This was always there, but the new background probes in 0.3.52 started hitting it.
- Saved ONVIF results without real evidence (no maker, model, firmware, ONVIF login prompt or video-device announcement) are dropped on startup. Real cameras get re-found by discovery within minutes.

## 0.3.55 — 2026-10-19

- NAS boxes and Windows PCs answer ONVIF discovery too ("I'm a computer"), and 0.3.51-0.3.54 counted any answer as a camera. Only devices that say they're a video transmitter count now, and the wrong results saved by those versions are dropped on startup.

## 0.3.54 — 2026-10-19

Camera firmware check.

- Cameras' firmware is checked against known-exploited bugs. For Hikvision (CVE-2021-36260, CVE-2017-7921) and Dahua (CVE-2021-33044, CVE-2021-33045), firmware built before the vendor's fix date is flagged as affected, with a critical recommendation to move the camera to local-only. If a camera won't say what firmware it runs, you're told it couldn't be checked rather than that it's fine.
- Makers on CISA's Known Exploited Vulnerabilities list without a version cut-off (Reolink, Amcrest, TVT, GeoVision, Edimax) get a warning to check the model by hand. The list is downloaded from cisa.gov once a day, and a copy is built in for when that isn't possible.
- Firmware build dates are shown on device cards, and cameras on firmware five or more years old get a recommendation. Cheap cameras rarely get updates.
- Xiongmai (XMEye) cameras are recognised from their firmware even when they report "H264" as the maker and UniFi doesn't know the vendor, so the XMEye advisory now reaches them.
- Fixed the Dahua advisory and the port 9530 recommendation, which listed two Hikvision CVEs as Dahua's.

## 0.3.53 — 2026-10-19

- New services: `unifiblocker.scan_device`, `unifiblocker.run_quantify` and `unifiblocker.onvif_discover`, so automations can run the tools.
- New event: `unifiblocker_new_camera`, fired once when a device is first seen as a camera. Cameras already on the network when you update don't fire it. The README has an example automation.
- Learned rules show at the bottom of the Identify page, where you can change their category or delete them. Before, a wrong rule stuck forever.
- Rules are no longer learned from randomized (private) MAC addresses. Their first bytes are random, so a MAC rule from one would match unrelated devices.

## 0.3.52 — 2026-10-19

Scan and ONVIF results that last.

- ONVIF results are now saved by MAC. A camera keeps its ONVIF identity across restarts and when it changes IP, instead of going back to unknown until the next discovery.
- ONVIF discovery runs at startup and then every 6 hours, not just once. Devices whose port scan shows a likely ONVIF port get probed directly. Probes run in the background so they never hold up a poll, and devices without ONVIF aren't probed again until a week has passed.
- Port scans are redone when a device changes IP or the scan is over a week old. Devices that were already scanned are no longer rescanned after every restart.

## 0.3.51 — 2026-10-19

Fewer devices wrongly called cameras.

- Ordinary ports no longer make a device a camera on their own: 8009 (Chromecast), 9000, 10000, 7681, 1935, 6000, 81 and friends now only count next to a real camera port like RTSP, ONVIF or the Dahua/Hikvision/XMEye protocols, or in pairs. A box that also shares files or takes remote desktop (Blue Iris PCs, NAS boxes) isn't called a camera for serving RTSP.
- Scans saved by older versions are re-judged by these rules, so devices they got wrong are fixed without rescanning.
- Hostnames are matched on whole words, so "camille-laptop" and "kids-ipad" are no longer cameras, while "frontcam", "DS-2CD2143..." and "DH-IPC-..." still are.
- Vendor names are matched on whole words too: "Ring" no longer matches every "...Engineering Co.", and "ACTi" no longer matches Actiontec.
- A camera chip maker (HiSilicon, Ingenic...) on its own is no longer "camera, high confidence". It's high with a camera-like hostname, medium with no hostname, and low otherwise.
- A device that answers ONVIF but wants a login now counts as a camera. So does one that answered ONVIF discovery, even when the follow-up probe needed a password. Both used to be thrown away.
- The XMEye and P2P cloud recommendations describe what was actually seen (a port that's open) instead of claiming the device is talking to China. The P2P one now offers local-only instead of a port block, and a single common port only triggers it on a camera.
- Fixed a socket leak in the NetBIOS probe and ONVIF discovery.

## 0.3.50 — 2026-10-19

- The usage report's Preview read the integration's manifest from disk inside Home Assistant's event loop, which Home Assistant flags as a blocking call. It now gets the version from Home Assistant when the integration loads.

## 0.3.49 — 2026-10-19

- 0.3.48 broke the sidebar panel: none of its commands registered, so it showed nothing. Fixed.

## 0.3.48 — 2026-10-19

- New: an opt-in usage and issue report, off unless you turn it on. It's the "Help improve UniFi Blocker" card at the bottom of Overview, with a Preview of the exact JSON. Once a day it sends counts and versions only (device counts by category, which tools get used, poll times, controller API errors, warnings logged per module) so problems on other people's networks can be found. Never MACs, IPs, names, vendor strings or entity ids, and the whole report is refused if anything like that turns up. The full list is in the README under "Privacy and the opt-in usage report".

## 0.3.47 — 2026-10-19

- The device lists on New devices, Quarantined devices, Suspicious devices, All clients detail and the two review binary sensors are far bigger than the recorder's 16 KB limit, so Home Assistant logged five warnings every poll. Those lists are now kept out of history. They're still on the entities, so dashboards and templates work as before.
- Each poll enriched every client once per entity. It's done once per poll now, which fixes Home Assistant's "Updating state ... took 0.95 seconds" warning.

## 0.3.46 — 2026-10-19

Quieter logs.

- Newer UniFi Network versions don't have the `stat/event` endpoint. The integration logged an error for it on every poll. It now checks once, notes it at info level, and stops asking.
- minerstat.com started refusing unauthenticated requests. When it fails, the integration warns once and retries every 10 minutes instead of on every poll. Miner profitability numbers stay empty until that's sorted out.

## 0.3.45 — 2026-10-19

Cleanup from the HACS review.

- `unifiblocker_saved_config.json` is gone. It's deleted on startup if an older version left one behind. To change the controller address or login, use Reconfigure on the integration instead of removing and re-adding it.
- The local-only subnet and auto-scan count options actually do something now, and changing options reloads the integration. The two subnet fields are merged into one, which has to be a /24. Devices you already assigned keep their current address.
- Setting auto-scan count to 0 turns auto-scan off.
- The Configure dialog works again on newer Home Assistant versions.
- ONVIF and deep-scan HTTPS probes reuse Home Assistant's SSL context instead of building a new one (and reading the CA bundle from disk) on every probe.
- The deep scan uses Home Assistant's shared mDNS instance instead of starting its own. mDNS results also map to categories properly now; they never matched before.

## 0.3.44 — 2026-10-18

More fixes, mostly to the scan and recommendation tools.

- Critical recommendations were sorted to the bottom of the list. They're at the top now.
- Cameras found by ONVIF, a port scan or set by hand weren't counted as cameras, so they were missing from the exposed-camera warnings and recommendations.
- The Hikvision, Dahua, XMEye, EZVIZ, Imou, Reolink and Foscam advisories only fired when UniFi's vendor string matched exactly, which it almost never does. They match on the vendor name now, and on the ONVIF manufacturer too.
- Quantify no longer saves every guess as a permanent manual category. High-confidence results are applied, everything else is shown as a suggestion you can accept, and you can see what it found for each device. Its guesses no longer train the learned rules either; only categories you set yourself do.
- You can clear a manual category from the device card so automatic detection takes over again.
- Renaming a device from the panel stuck until the next poll, then got overwritten. It sticks now. Your UniFi alias also wins over the device's hostname.
- Port scan results survive a panel reload, and Scan Ports on the recommendations page shows its results instead of doing nothing visible.
- The "local-only firewall rule" warning pointed at a button that didn't exist and showed up even with no devices assigned. It only shows when an assigned device is missing its rule, and the Local Only page has a "Create Missing Rules" button.
- IP history shows on device cards again.

## 0.3.43 — 2026-10-17

Bug fix and security release. Everything here was broken in 0.3.42 and earlier.

- Device enrichment crashed for every client, so categories, suspicion flags and ONVIF details never made it to the panel (and the log filled with tracebacks). Fixed.
- The panel now escapes everything it gets from the controller. Device hostnames, ONVIF replies and miner API responses come from devices on your network, and before this a device could inject script into the panel.
- The sidebar panel and all of its commands now require an HA admin. Previously any HA user could open it and block devices.
- The controller password is no longer saved to `unifiblocker_saved_config.json`. If an older version left it there, it gets removed on the next restart.
- Fixed duplicate entries in the MAC vendor table. Raspberry Pi and Realtek devices were being reported as crypto miners, and some Dahua cameras as Hikvision.
- Fixed duplicate ports in the scanner list and stopped TCP-scanning UDP-only services.
- "Ensure rule" for local-only devices never found the rules it had already created, so it made a new duplicate rule every time. It now recognises existing rules.
- Auto-scan only scanned the first 5 new devices it ever saw. The rest now get picked up on later polls.
- The device store is no longer written to disk on every poll.
- The panel is removed properly when the integration is unloaded or reloaded.
- Minimum Home Assistant version corrected to 2024.7.0 (it already needed that).

## 0.1.0 — 2026-04-08

- Initial release
- Direct UniFi OS API integration (UCG Max, UDM, UDM Pro)
- Config flow with connection test
- Device review queue: new / trusted / ignored / quarantined states
- MAC vendor lookup (200+ OUI prefixes)
- Persistent device store
- Sensors: connected clients, new devices, blocked, quarantined, trusted, wireless, wired, all-client detail
- Binary sensor: devices pending review
- Services: trust, ignore, quarantine, block, unblock, reconnect
- Lovelace dashboard with 5 views
- HACS-ready packaging
