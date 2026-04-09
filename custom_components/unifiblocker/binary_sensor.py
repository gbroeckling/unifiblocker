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
    async_add_entities([
        NewDevicesPendingBinarySensor(coordinator, entry),
        SuspiciousTrafficBinarySensor(coordinator, entry),
        ControllerReachableBinarySensor(coordinator, entry),
    ])


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
                self._data.enrich_client(c) for c in new
            ],
        }


class SuspiciousTrafficBinarySensor(
    CoordinatorEntity[UniFiBlockerCoordinator], BinarySensorEntity
):
    """ON when any connected client has suspicious traffic indicators."""

    _attr_has_entity_name = True
    _attr_name = "Suspicious traffic detected"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:alert-octagon"

    def __init__(
        self,
        coordinator: UniFiBlockerCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_suspicious_traffic"

    @property
    def _data(self) -> UniFiBlockerData | None:
        return self.coordinator.data

    @property
    def is_on(self) -> bool | None:
        if not self._data:
            return None
        return self._data.suspicious_count > 0

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        susp = self._data.suspicious_clients
        enriched = [self._data.enrich_client(c) for c in susp]
        enriched.sort(key=lambda x: x.get("suspicion_score", 0), reverse=True)
        return {
            "count": len(enriched),
            "devices": enriched,
        }


class ControllerReachableBinarySensor(
    CoordinatorEntity[UniFiBlockerCoordinator], BinarySensorEntity
):
    """ON when the UCG Max controller is reachable and authenticated."""

    _attr_has_entity_name = True
    _attr_name = "Controller reachable"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_icon = "mdi:server-network"

    def __init__(
        self,
        coordinator: UniFiBlockerCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_controller_reachable"

    @property
    def _data(self) -> UniFiBlockerData | None:
        return self.coordinator.data

    @property
    def is_on(self) -> bool | None:
        if not self._data:
            return None
        return self._data.health.get("connection_ok", False)

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        h = self._data.health
        return {
            "hostname": h.get("hostname", ""),
            "version": h.get("version", ""),
            "uptime": h.get("uptime", 0),
            "error": h.get("error", ""),
        }
