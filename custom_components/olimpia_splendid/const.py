"""Costanti per l'integrazione Olimpia Splendid Unico."""

from homeassistant.components.climate import (
    HVACMode,
)

DOMAIN = "olimpia_splendid"

DEFAULT_PORT = 2000
SCAN_INTERVAL = 30

# Mapping mode device → HVACMode HA
MODE_DEVICE_TO_HA = {
    0: HVACMode.HEAT,
    1: HVACMode.COOL,
    2: HVACMode.DRY,
    3: HVACMode.FAN_ONLY,
    4: HVACMode.AUTO,
}

MODE_HA_TO_DEVICE = {v: k for k, v in MODE_DEVICE_TO_HA.items()}

# Mapping fan device → stringa HA
FAN_DEVICE_TO_HA = {
    0: "low",
    1: "mid",
    2: "high",
    3: "auto",
}

FAN_HA_TO_DEVICE = {v: k for k, v in FAN_DEVICE_TO_HA.items()}

# Swing
SWING_DEVICE_TO_HA = {
    0: "off",
    1: "on",
}
