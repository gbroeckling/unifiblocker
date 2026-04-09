"""Sensor platform for UniFi Blocker."""
from __future__ import annotations

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import UniFiBlockerCoordinator, UniFiBlockerData


from .vendor_lookup import lookup_vendor_safe


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor entities."""
    coordinator: UniFiBlockerCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        [
            TotalClientsSensor(coordinator, entry),
            NewDevicesSensor(coordinator, entry),
            BlockedDevicesSensor(coordinator, entry),
            QuarantinedDevicesSensor(coordinator, entry),
            TrustedDevicesSensor(coordinator, entry),
            WirelessClientsSensor(coordinator, entry),
            WiredClientsSensor(coordinator, entry),
            AllClientDetailsSensor(coordinator, entry),
        ]
    )


class _BaseSensor(CoordinatorEntity[UniFiBlockerCoordinator], SensorEntity):
    """Base class for UniFi Blocker sensors."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: UniFiBlockerCoordinator,
        entry: ConfigEntry,
        key: str,
        name: str,
        icon: str,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_name = name
        self._attr_icon = icon
        self._key = key

    @property
    def _data(self) -> UniFiBlockerData | None:
        return self.coordinator.data


class TotalClientsSensor(_BaseSensor):
    """Number of currently connected clients."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "total_clients", "Connected clients", "mdi:devices")

    @property
    def native_value(self) -> int | None:
        return self._data.total_clients if self._data else None


class NewDevicesSensor(_BaseSensor):
    """Number of unreviewed (new) devices."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "new_devices", "New devices", "mdi:alert-decagram")

    @property
    def native_value(self) -> int | None:
        return self._data.new_count if self._data else None

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        return {
            "devices": [self._data.enrich_client(c) for c in self._data.new_devices],
        }


class BlockedDevicesSensor(_BaseSensor):
    """Number of currently blocked clients on the controller."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "blocked_devices", "Blocked devices", "mdi:block-helper")

    @property
    def native_value(self) -> int | None:
        return self._data.blocked_count if self._data else None


class QuarantinedDevicesSensor(_BaseSensor):
    """Number of devices marked quarantined in the local store."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "quarantined_devices", "Quarantined devices", "mdi:shield-alert")

    @property
    def native_value(self) -> int | None:
        if not self._data:
            return None
        return len(self._data.quarantined_macs)

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        qmacs = self._data.quarantined_macs
        return {
            "devices": [
                self._data.enrich_client(c)
                for c in self._data.clients
                if c.get("mac", "").lower() in qmacs
            ],
        }


class TrustedDevicesSensor(_BaseSensor):
    """Number of devices marked as trusted."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "trusted_devices", "Trusted devices", "mdi:shield-check")

    @property
    def native_value(self) -> int | None:
        return self._data.trusted_count if self._data else None


class WirelessClientsSensor(_BaseSensor):
    """Number of wireless (Wi-Fi) clients currently connected."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "wireless_clients", "Wireless clients", "mdi:wifi")

    @property
    def native_value(self) -> int | None:
        if not self._data:
            return None
        return sum(1 for c in self._data.clients if not c.get("is_wired", False))


class WiredClientsSensor(_BaseSensor):
    """Number of wired clients currently connected."""

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "wired_clients", "Wired clients", "mdi:ethernet")

    @property
    def native_value(self) -> int | None:
        if not self._data:
            return None
        return sum(1 for c in self._data.clients if c.get("is_wired", False))


class AllClientDetailsSensor(_BaseSensor):
    """Sensor whose attributes contain a full enriched client table.

    The *state* is the total client count; the real value is in the
    ``clients`` attribute list which powers dashboard templates.
    """

    _attr_state_class = None  # Not a measurement

    def __init__(self, coordinator: UniFiBlockerCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "all_clients", "All clients detail", "mdi:format-list-bulleted")

    @property
    def native_value(self) -> int | None:
        return self._data.total_clients if self._data else None

    @property
    def extra_state_attributes(self) -> dict | None:
        if not self._data:
            return None
        return {"clients": self._data.all_clients_enriched()}
