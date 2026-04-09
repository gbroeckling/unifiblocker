"""Config flow for UniFi Blocker."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import voluptuous as vol
from homeassistant import config_entries

_LOGGER = logging.getLogger(__name__)

DOMAIN = "unifiblocker"

# Saved config file — survives integration removal.
# Stored in HA's config dir, NOT inside custom_components (which HACS replaces).
_SAVED_CONFIG_FILE = "unifiblocker_saved_config.json"


async def _get_saved_config(hass) -> dict[str, Any]:
    """Load previously used config from disk (async-safe)."""
    path = os.path.join(hass.config.config_dir, _SAVED_CONFIG_FILE)
    try:
        return await hass.async_add_executor_job(_read_json, path)
    except Exception:
        return {}


async def _save_config_async(hass, data: dict[str, Any]) -> None:
    """Save config to disk (async-safe)."""
    path = os.path.join(hass.config.config_dir, _SAVED_CONFIG_FILE)
    try:
        await hass.async_add_executor_job(_write_json, path, data)
    except Exception:
        _LOGGER.warning("Could not save config", exc_info=True)


def _read_json(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def _write_json(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


def _build_schema(saved: dict[str, Any]) -> vol.Schema:
    """Build the form schema, pre-filling from saved config."""
    pw = saved.get("password", "")
    return vol.Schema(
        {
            vol.Required("host", default=saved.get("host", "")): str,
            vol.Required("username", default=saved.get("username", "")): str,
            vol.Required("password", default=pw): str,
            vol.Optional("site", default=saved.get("site", "default")): str,
            vol.Optional("verify_ssl", default=saved.get("verify_ssl", False)): bool,
            vol.Optional("scan_interval", default=saved.get("scan_interval", 60)): int,
        }
    )


class UniFiBlockerConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for UniFi Blocker."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        """Handle the initial setup step."""
        # Abort immediately if already configured — no form, no 500.
        if self._async_current_entries():
            return self.async_abort(reason="already_configured")

        errors: dict[str, str] = {}
        saved = await _get_saved_config(self.hass)

        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

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
                # Save config for future re-adds.
                await _save_config_async(self.hass, user_input)
                return self.async_create_entry(
                    title=f"UniFi Blocker ({user_input['host']})",
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=_build_schema(saved),
            errors=errors,
            description_placeholders={
                "has_saved": "true" if saved.get("host") else "false",
            },
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
                vol.Optional("local_subnet", default=cur.get("local_subnet", "192.168.2")): str,
                vol.Optional("local_cidr", default=cur.get("local_cidr", "192.168.2.0/24")): str,
                vol.Optional("auto_scan_count", default=cur.get("auto_scan_count", 5)): int,
            }),
        )
