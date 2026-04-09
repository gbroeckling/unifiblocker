"""Config flow for UniFi Blocker."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries

_LOGGER = logging.getLogger(__name__)

DOMAIN = "unifiblocker"

_SCHEMA = vol.Schema(
    {
        vol.Required("host"): str,
        vol.Required("username"): str,
        vol.Required("password"): str,
        vol.Optional("site", default="default"): str,
        vol.Optional("verify_ssl", default=False): bool,
        vol.Optional("scan_interval", default=60): int,
    }
)


class UniFiBlockerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UniFi Blocker."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial setup step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

            # Lazy import — only pulled in when the user submits the form.
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
                errors["base"] = "invalid_auth"
            except UniFiConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Connection test failed")
                errors["base"] = "unknown"
            finally:
                await api.close()

            if not errors:
                return self.async_create_entry(
                    title=f"UniFi Blocker ({user_input['host']})",
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user", data_schema=_SCHEMA, errors=errors
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        return _OptionsFlow(config_entry)


class _OptionsFlow(config_entries.OptionsFlow):

    def __init__(self, config_entry) -> None:
        self.config_entry = config_entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        cur = {**self.config_entry.data, **self.config_entry.options}
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({
                vol.Optional("scan_interval", default=cur.get("scan_interval", 60)): int,
                vol.Optional("verify_ssl", default=cur.get("verify_ssl", False)): bool,
            }),
        )
