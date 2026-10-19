"""Config flow for UniFi Blocker."""
from __future__ import annotations

import ipaddress
import logging
import os
from typing import Any

import voluptuous as vol
from homeassistant import config_entries

_LOGGER = logging.getLogger(__name__)

DOMAIN = "unifiblocker"

DEFAULT_LOCAL_CIDR = "192.168.2.0/24"
DEFAULT_AUTO_SCAN_COUNT = 5

# Older versions kept the form input here so re-adding was quicker. It held
# the controller password, so it's gone; reconfigure covers the same need.
_OLD_SAVED_CONFIG_FILE = "unifiblocker_saved_config.json"


async def async_remove_old_saved_config(hass) -> None:
    """Delete the saved-config file older versions left in the config dir."""
    path = os.path.join(hass.config.config_dir, _OLD_SAVED_CONFIG_FILE)

    def _remove() -> None:
        if os.path.exists(path):
            os.remove(path)

    try:
        await hass.async_add_executor_job(_remove)
    except OSError:
        _LOGGER.warning("Could not remove %s", path, exc_info=True)


def _connection_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required("host", default=defaults.get("host", "")): str,
            vol.Required("username", default=defaults.get("username", "")): str,
            vol.Required("password"): str,
            vol.Optional("site", default=defaults.get("site", "default")): str,
            vol.Optional("verify_ssl", default=defaults.get("verify_ssl", False)): bool,
        }
    )


async def _test_connection(user_input: dict[str, Any]) -> str | None:
    """Try to log in. Returns an error key, or None if it worked."""
    from .unifi_api import UniFiApi, UniFiAuthError, UniFiConnectionError

    api = UniFiApi(
        host=user_input["host"],
        username=user_input["username"],
        password=user_input["password"],
        site=user_input.get("site", "default"),
        verify_ssl=user_input.get("verify_ssl", False),
    )
    try:
        await api.test_connection()
    except UniFiAuthError:
        return "invalid_auth"
    except UniFiConnectionError:
        return "cannot_connect"
    except Exception:
        _LOGGER.exception("Connection test failed")
        return "unknown"
    finally:
        await api.close()
    return None


def local_prefix_from_cidr(cidr: str) -> str:
    """'192.168.2.0/24' -> '192.168.2'."""
    return str(ipaddress.ip_network(cidr, strict=False).network_address).rsplit(".", 1)[0]


class UniFiBlockerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UniFi Blocker."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial setup step."""
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")

        errors: dict[str, str] = {}
        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()
            error = await _test_connection(user_input)
            if error:
                errors["base"] = error
            else:
                return self.async_create_entry(
                    title=f"UniFi Blocker ({user_input['host']})",
                    data=user_input,
                )

        defaults = user_input or {}
        return self.async_show_form(
            step_id="user",
            data_schema=_connection_schema(defaults).extend({
                vol.Optional("scan_interval", default=defaults.get("scan_interval", 60)): int,
            }),
            errors=errors,
        )

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Change the controller address or login without removing the integration."""
        entry = self.hass.config_entries.async_get_entry(self.context["entry_id"])
        errors: dict[str, str] = {}
        if user_input is not None:
            error = await _test_connection(user_input)
            if error:
                errors["base"] = error
            else:
                # The update listener in __init__ reloads the entry.
                self.hass.config_entries.async_update_entry(
                    entry,
                    title=f"UniFi Blocker ({user_input['host']})",
                    data={**entry.data, **user_input},
                )
                return self.async_abort(reason="reconfigure_successful")

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_connection_schema(user_input or dict(entry.data)),
            errors=errors,
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        return _OptionsFlow()


class _OptionsFlow(config_entries.OptionsFlow):
    # Looks the entry up through self.handler (the entry id), which works on
    # every HA version we support. Newer HA no longer lets us assign
    # self.config_entry.

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        entry = self.hass.config_entries.async_get_entry(self.handler)
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                net = ipaddress.ip_network(user_input["local_cidr"], strict=False)
                if net.version != 4 or net.prefixlen != 24:
                    raise ValueError
                user_input["local_cidr"] = str(net)
            except ValueError:
                errors["local_cidr"] = "invalid_cidr"
            if not errors:
                return self.async_create_entry(title="", data=user_input)

        cur = {**entry.data, **entry.options, **(user_input or {})}
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional("scan_interval", default=cur.get("scan_interval", 60)): vol.All(
                    int, vol.Range(min=10)
                ),
                vol.Optional("verify_ssl", default=cur.get("verify_ssl", False)): bool,
                vol.Optional("local_cidr", default=cur.get("local_cidr", DEFAULT_LOCAL_CIDR)): str,
                vol.Optional(
                    "auto_scan_count", default=cur.get("auto_scan_count", DEFAULT_AUTO_SCAN_COUNT)
                ): vol.All(int, vol.Range(min=0, max=50)),
            }),
            errors=errors,
        )
