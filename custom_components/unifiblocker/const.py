"""Constants for UniFi Blocker."""

DOMAIN = "unifiblocker"
PLATFORMS: list[str] = ["sensor", "binary_sensor"]

# ── Config keys ──────────────────────────────────────────────────────
CONF_HOST = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_SITE = "site"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"

# ── Defaults ─────────────────────────────────────────────────────────
DEFAULT_SITE = "default"
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_VERIFY_SSL = False

# ── UniFi OS API paths (UCG Max / Dream Machine style) ──────────────
API_LOGIN = "/api/auth/login"
API_CLIENTS = "/proxy/network/api/s/{site}/stat/sta"
API_ALL_USERS = "/proxy/network/api/s/{site}/rest/user"
API_DEVICE_CMD = "/proxy/network/api/s/{site}/cmd/stamgr"
API_DEVICES = "/proxy/network/api/s/{site}/stat/device"
API_SYSINFO = "/proxy/network/api/s/{site}/stat/sysinfo"
API_EVENTS = "/proxy/network/api/s/{site}/stat/event"
API_ROGUE_AP = "/proxy/network/api/s/{site}/stat/rogueap"
API_HEALTH = "/proxy/network/api/s/{site}/stat/health"
API_DPI = "/proxy/network/api/s/{site}/stat/stadpi"
API_USER = "/proxy/network/api/s/{site}/rest/user/{user_id}"
API_FIREWALL_RULES = "/proxy/network/api/s/{site}/rest/firewallrule"
API_FIREWALL_RULE = "/proxy/network/api/s/{site}/rest/firewallrule/{rule_id}"
API_NETWORKS = "/proxy/network/api/s/{site}/rest/networkconf"

# ── Device states ────────────────────────────────────────────────────
STATE_NEW = "new"
STATE_TRUSTED = "trusted"
STATE_IGNORED = "ignored"
STATE_QUARANTINED = "quarantined"

# ── Storage ──────────────────────────────────────────────────────────
STORAGE_KEY = DOMAIN
STORAGE_VERSION = 1
