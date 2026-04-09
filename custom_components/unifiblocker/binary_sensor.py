"""Binary sensor platform for UniFi Blocker."""
from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import UniFiBlockerCoordinator, UniFiBlockerData


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensor entities."""
    coordinator: UniFiBlockerCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities([NewDevicesPendingBinarySensor(coordinator, entry)])


class NewDevicesPendingBinarySensor(
    CoordinatorEntity[UniFiBlockerCoordinator], BinarySensorEntity
):
    """ON when there are new devices awaiting review."""

    _attr_has_entity_name = True
    _attr_name = "Devices pending review"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:account-question"

    def __init__(
        self,
        coordinator: UniFiBlockerCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_pending_review"

    @property
    def _data(self) -> UniFiBlockerData | None:
        return self.coordinator.data

    @property
    def is_on(self) -> bool | None:
        if not self._data:
            return None
        return self._data.new_count > 0

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        new = self._data.new_devices
        return {
            "count": len(new),
            "devices": [
                {
                    "mac": c.get("mac"),
                    "hostname": c.get("hostname", ""),
                    "ip": c.get("ip", ""),
                    "oui": c.get("oui", ""),
                }
                for c in new
            ],
        }
