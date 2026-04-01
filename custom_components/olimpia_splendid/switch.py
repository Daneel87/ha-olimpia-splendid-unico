"""Switch entity per Olimpia Splendid Unico — Scheduler control."""

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import OlimpiaCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: OlimpiaCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([OlimpiaSchedulerSwitch(coordinator, entry)])


class OlimpiaSchedulerSwitch(CoordinatorEntity[OlimpiaCoordinator], SwitchEntity):
    """Switch per abilitare/disabilitare lo scheduler interno del device."""

    _attr_has_entity_name = True
    _attr_name = "Scheduler"
    _attr_icon = "mdi:calendar-clock"

    def __init__(
        self, coordinator: OlimpiaCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        creds = entry.data.get("credentials", {})
        device_uid = creds.get("device_uid", entry.entry_id)
        self._attr_unique_id = f"{device_uid}_scheduler"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_uid)},
        )

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if not data:
            return None
        return bool(data.get("scheduler"))

    async def async_turn_on(self, **kwargs) -> None:
        ok = await self.coordinator.async_send_command("toggle_scheduler", True)
        if ok:
            self._update_scheduler_state(True)

    async def async_turn_off(self, **kwargs) -> None:
        ok = await self.coordinator.async_send_command("toggle_scheduler", False)
        if ok:
            self._update_scheduler_state(False)

    def _update_scheduler_state(self, enabled: bool) -> None:
        if self.coordinator.data:
            data = dict(self.coordinator.data)
            data["scheduler"] = enabled
            self.coordinator.async_set_updated_data(data)
