# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you find a security issue in UniFi Blocker, **please do not open a public GitHub issue.**

Instead, report it privately:

1. Go to the [Security Advisories](https://github.com/gbroeckling/unifiblocker/security/advisories) page
2. Click **"Report a vulnerability"**
3. Describe the issue and how to reproduce it

You should receive a response within 7 days. If the issue is confirmed, a fix will be released as soon as practical and you will be credited in the changelog (unless you prefer to remain anonymous).

## What Counts as a Security Issue

- Credential leakage (controller passwords in logs, attributes, or storage)
- Injection vulnerabilities in service call handling
- Unauthorized block/unblock actions without proper HA authentication
- Path traversal or arbitrary file access

## What Doesn't Count

- Issues that require physical access to the Home Assistant instance
- Denial of service against a local-only integration
- Bugs that don't have a security impact

## Security Measures in Place

- Controller credentials are stored in HA's encrypted config entry store, not in plain files
- All API communication uses HTTPS
- Service calls require Home Assistant authentication
- MAC addresses are normalized and validated before being sent to the controller API
