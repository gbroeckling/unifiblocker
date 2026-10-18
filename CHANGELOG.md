# Changelog

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
