# Changelog

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
