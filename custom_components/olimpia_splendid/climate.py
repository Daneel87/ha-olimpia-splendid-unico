"""Climate entity per Olimpia Splendid Unico."""

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    MODE_DEVICE_TO_HA,
    MODE_HA_TO_DEVICE,
    FAN_DEVICE_TO_HA,
    FAN_HA_TO_DEVICE,
    SWING_DEVICE_TO_HA,
)
from .coordinator import OlimpiaCoordinator
from .olimpia.enums import Mode, Fan

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Olimpia Splendid climate entity."""
    coordinator: OlimpiaCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([OlimpiaClimateEntity(coordinator, entry)])


class OlimpiaClimateEntity(CoordinatorEntity[OlimpiaCoordinator], ClimateEntity):
    """Climate entity per Olimpia Splendid Unico."""

    _attr_has_entity_name = True
    _attr_name = None
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_hvac_modes = [
        HVACMode.OFF,
        HVACMode.HEAT,
        HVACMode.COOL,
        HVACMode.DRY,
        HVACMode.FAN_ONLY,
        HVACMode.AUTO,
    ]
    _attr_fan_modes = ["low", "mid", "high", "auto"]
    _attr_swing_modes = ["off", "on"]
    _attr_min_temp = 16
    _attr_max_temp = 30
    _attr_target_temperature_step = 1.0
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
        | ClimateEntityFeature.FAN_MODE
        | ClimateEntityFeature.SWING_MODE
    )

    def __init__(
        self, coordinator: OlimpiaCoordinator, entry: ConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        creds = entry.data.get("credentials", {})
        device_uid = creds.get("device_uid", entry.entry_id)
        self._attr_unique_id = device_uid
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device_uid)},
            name=entry.data.get("device_name", "Olimpia Splendid Unico"),
            manufacturer="Olimpia Splendid",
            model=entry.data.get("device_model", "Unico"),
            sw_version=entry.data.get("device_fw_version"),
        )

    @property
    def _data(self) -> dict:
        return self.coordinator.data or {}

    @property
    def hvac_mode(self) -> HVACMode:
        if not self._data.get("power"):
            return HVACMode.OFF
        mode = self._data.get("mode")
        return MODE_DEVICE_TO_HA.get(mode, HVACMode.AUTO)

    @property
    def current_temperature(self) -> float | None:
        return self._data.get("room_temp")

    @property
    def target_temperature(self) -> float | None:
        return self._data.get("set_temp")

    @property
    def fan_mode(self) -> str | None:
        fan = self._data.get("fan")
        return FAN_DEVICE_TO_HA.get(fan)

    @property
    def swing_mode(self) -> str | None:
        flap = self._data.get("flap")
        return SWING_DEVICE_TO_HA.get(flap, "off")

    def _optimistic_update(self, **fields) -> None:
        """Aggiorna coordinator data ottimisticamente dopo un comando."""
        if self.coordinator.data:
            data = dict(self.coordinator.data)
            data.update(fields)
            self.coordinator.async_set_updated_data(data)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        if hvac_mode == HVACMode.OFF:
            ok = await self.coordinator.async_send_command("power_off")
            if ok:
                self._optimistic_update(power=False)
        else:
            if not self._data.get("power"):
                ok = await self.coordinator.async_send_command("power_on")
                if not ok:
                    return
            device_mode = MODE_HA_TO_DEVICE.get(hvac_mode)
            if device_mode is not None:
                ok = await self.coordinator.async_send_command(
                    "set_mode", Mode(device_mode)
                )
                if ok:
                    self._optimistic_update(power=True, mode=device_mode)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temp = kwargs.get(ATTR_TEMPERATURE)
        if temp is not None:
            ok = await self.coordinator.async_send_command(
                "set_temperature", temp
            )
            if ok:
                self._optimistic_update(set_temp=temp)

    async def async_set_fan_mode(self, fan_mode: str) -> None:
        device_fan = FAN_HA_TO_DEVICE.get(fan_mode)
        if device_fan is not None:
            ok = await self.coordinator.async_send_command(
                "set_fan", Fan(device_fan)
            )
            if ok:
                self._optimistic_update(fan=device_fan)

    async def async_set_swing_mode(self, swing_mode: str) -> None:
        swing = swing_mode == "on"
        ok = await self.coordinator.async_send_command(
            "toggle_flap", swing
        )
        if ok:
            self._optimistic_update(flap=1 if swing else 0)
