# Changelog

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
