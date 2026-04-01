"""Config flow per Olimpia Splendid Unico."""

import asyncio
import json
import logging
import socket
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, DEFAULT_PORT
from .olimpia.client import OlimpiaClient
from .olimpia.credentials import load_credentials

_LOGGER = logging.getLogger(__name__)


class OlimpiaSplendidConfigFlow(ConfigFlow, domain=DOMAIN):
    """Config flow duale: IP manuale o BLE setup."""

    VERSION = 1

    def __init__(self) -> None:
        self._ble_address: str | None = None
        self._ble_devices: list[dict] = []
        self._ble_pin: int = 0
        self._ble_ssid: str = ""
        self._ble_password: str = ""
        self._pairing_task: asyncio.Task | None = None
        self._pairing_result: dict | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step iniziale: scelta metodo."""
        return self.async_show_menu(
            step_id="user",
            menu_options=["ble_scan", "manual_ip"],
        )

    # --- Path A: IP manuale ---

    async def async_step_manual_ip(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Inserimento IP manuale."""
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input["host"]
            port = user_input.get("port", DEFAULT_PORT)
            creds_json = user_input.get("credentials_json", "").strip()

            creds = None
            if creds_json:
                # Parse pasted credentials JSON
                try:
                    creds = json.loads(creds_json)
                    required = ("user_hash", "user_counter", "device_uid", "crypto")
                    if not all(k in creds for k in required):
                        errors["base"] = "invalid_credentials_json"
                        creds = None
                except (json.JSONDecodeError, ValueError):
                    errors["base"] = "invalid_credentials_json"

            if not creds and not errors:
                # Fallback: load from disk
                creds = await self.hass.async_add_executor_job(
                    load_credentials, host
                )
                if not creds:
                    errors["base"] = "no_credentials"

            if creds and not errors:
                # Tenta connessione + auth
                try:
                    ok = await self.hass.async_add_executor_job(
                        self._test_connection, host, port, creds
                    )
                    if ok:
                        device_uid = creds.get("device_uid", host)
                        await self.async_set_unique_id(device_uid)
                        self._abort_if_unique_id_configured()

                        return self.async_create_entry(
                            title=f"Olimpia Splendid ({host})",
                            data={
                                "host": host,
                                "port": port,
                                "credentials": creds,
                                "device_uid": device_uid,
                            },
                        )
                    else:
                        errors["base"] = "invalid_auth"
                except (ConnectionError, OSError, socket.timeout):
                    errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="manual_ip",
            data_schema=vol.Schema(
                {
                    vol.Required("host"): str,
                    vol.Optional("port", default=DEFAULT_PORT): int,
                    vol.Optional("credentials_json", default=""): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    def _test_connection(host: str, port: int, creds: dict) -> bool:
        """Test sync connessione + autenticazione."""
        client = OlimpiaClient(host, port)
        try:
            client.connect()
            return client.authenticate_from_dict(creds)
        finally:
            client.disconnect()

    # --- Path B: BLE setup ---

    async def async_step_ble_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Scan BLE per device Olimpia."""
        errors: dict[str, str] = {}

        if user_input is not None:
            self._ble_address = user_input["ble_device"]
            return await self.async_step_ble_pin()

        # Esegui scan
        from .olimpia_ble import OlimpiaBLE

        devices = await OlimpiaBLE.scan(timeout=10)
        olimpia_devices = devices

        if not olimpia_devices:
            errors["base"] = "ble_no_devices"
            return self.async_show_form(
                step_id="ble_scan",
                data_schema=vol.Schema({}),
                errors=errors,
            )

        self._ble_devices = olimpia_devices
        device_options = {
            d["address"]: f"{d['name']} ({d['address']}) RSSI:{d['rssi']}"
            for d in olimpia_devices
        }

        return self.async_show_form(
            step_id="ble_scan",
            data_schema=vol.Schema(
                {
                    vol.Required("ble_device"): vol.In(device_options),
                }
            ),
            errors=errors,
        )

    async def async_step_ble_pin(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Inserimento PIN e credenziali WiFi."""
        if user_input is not None:
            self._ble_pin = user_input["pin"]
            self._ble_ssid = user_input["ssid"]
            self._ble_password = user_input["wifi_password"]
            return await self.async_step_ble_pairing()

        return self.async_show_form(
            step_id="ble_pin",
            data_schema=vol.Schema(
                {
                    vol.Required("pin"): str,
                    vol.Required("ssid"): str,
                    vol.Required("wifi_password"): str,
                }
            ),
        )

    async def async_step_ble_pairing(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Esegue pairing BLE con progress."""
        if not self._pairing_task:
            self._pairing_task = self.hass.async_create_task(
                self._do_ble_pairing()
            )
            return self.async_show_progress(
                step_id="ble_pairing",
                progress_action="ble_pairing",
                progress_task=self._pairing_task,
            )

        # Task completato — HA ci richiama automaticamente
        try:
            await self._pairing_task
        except Exception:
            _LOGGER.exception("BLE pairing failed")
            return self.async_show_progress_done(next_step_id="ble_pairing_failed")

        if self._pairing_result:
            return self.async_show_progress_done(next_step_id="ble_pairing_done")

        return self.async_show_progress_done(next_step_id="ble_pairing_failed")

    async def async_step_ble_pairing_done(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Pairing riuscito — crea config entry."""
        creds = self._pairing_result
        host = creds.get("host", "")
        device_uid = creds.get("device_uid", host)

        if host:
            await self.async_set_unique_id(device_uid)
            self._abort_if_unique_id_configured()

            return self.async_create_entry(
                title=f"Olimpia Splendid ({host})",
                data={
                    "host": host,
                    "port": DEFAULT_PORT,
                    "credentials": creds,
                    "device_uid": device_uid,
                },
            )

        return self.async_abort(reason="ble_pairing_failed")

    async def async_step_ble_pairing_failed(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """BLE pairing fallito."""
        return self.async_abort(reason="ble_pairing_failed")

    async def _do_ble_pairing(self) -> None:
        """Task asincrono per BLE pairing + WiFi config."""
        from .olimpia_ble import OlimpiaBLE, ble_full_setup

        ble = OlimpiaBLE(verbose=True)
        try:
            from bleak import BleakScanner

            _LOGGER.debug("BLE scan for %s...", self._ble_address)
            device = await BleakScanner.find_device_by_address(
                self._ble_address, timeout=10
            )
            if device is None:
                _LOGGER.error("BLE device %s not found during scan", self._ble_address)
                return

            _LOGGER.debug("BLE connecting to %s (%s)...", device.name, device.address)
            await ble.connect(device)
            _LOGGER.debug("BLE connected, starting full setup...")

            result = await ble_full_setup(
                ble,
                pin=int(self._ble_pin),
                ssid=self._ble_ssid,
                password=self._ble_password,
                return_creds=True,
            )
            _LOGGER.debug("BLE full setup result: %s", type(result).__name__)
            if result and isinstance(result, dict):
                _LOGGER.debug("BLE pairing OK, host=%s", result.get("host"))
                self._pairing_result = result
            else:
                _LOGGER.error("BLE pairing returned falsy: %r", result)
        except Exception:
            _LOGGER.exception("BLE pairing exception")
            raise
        finally:
            await ble.disconnect()
            _LOGGER.debug("BLE disconnected")
