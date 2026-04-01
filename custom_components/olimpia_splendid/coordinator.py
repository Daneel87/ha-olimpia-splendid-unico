"""DataUpdateCoordinator per Olimpia Splendid Unico."""

import logging
import threading
import time as _time
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SCAN_INTERVAL
from .olimpia.client import OlimpiaClient

_LOGGER = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
RETRY_DELAYS = [3, 5]  # secondi tra tentativi
COMMAND_GRACE_PERIOD = 5.0  # secondi: salta poll dopo un comando recente


class OlimpiaCoordinator(DataUpdateCoordinator):
    """Coordinator per polling stato device Olimpia.

    Ogni operazione (poll o comando) apre una connessione TCP dedicata,
    esattamente come lo script CLI locale:
      connect → authenticate → comando(i) → disconnect
    Elimina tutti i problemi di sessioni long-lived (desync crypto,
    buffer corruption, timeout firmware).
    """

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL),
        )
        self.entry = entry
        self.host: str = entry.data["host"]
        self.port: int = entry.data.get("port", 2000)
        self.credentials: dict = dict(entry.data["credentials"])
        self._tcp_lock = threading.Lock()
        self._last_known_mode: int | None = None
        self._last_known_power: bool | None = None
        self._last_command_time: float = 0

    # --- Persistenza counter ---

    def _persist_counter(self, client: OlimpiaClient) -> None:
        """Salva user_counter aggiornato nel config entry."""
        new_counter = client._user_counter
        old_counter = self.credentials.get("user_counter")
        if new_counter != old_counter:
            _LOGGER.debug("Persisting user_counter: %s -> %s", old_counter, new_counter)
            self.credentials["user_counter"] = new_counter
            new_data = dict(self.entry.data)
            new_data["credentials"] = self.credentials
            self.hass.config_entries.async_update_entry(self.entry, data=new_data)

    # --- Connessione singola per operazione ---

    def _connect_and_auth(self) -> OlimpiaClient:
        """Crea client, connetti, autentica. Raise se fallisce dopo retry."""
        for attempt in range(MAX_ATTEMPTS):
            client = OlimpiaClient(self.host, self.port)
            client.verbose = True
            try:
                client.connect()
                ok = client.authenticate_from_dict(self.credentials)
                if ok:
                    _LOGGER.debug("Connected to %s (attempt %d)", self.host, attempt + 1)
                    return client
                _LOGGER.warning("Auth failed on attempt %d/%d", attempt + 1, MAX_ATTEMPTS)
            except (ConnectionError, OSError, Exception) as err:
                _LOGGER.warning("Connection attempt %d/%d failed: %s", attempt + 1, MAX_ATTEMPTS, err)

            client.disconnect()
            if attempt < len(RETRY_DELAYS):
                import time
                time.sleep(RETRY_DELAYS[attempt])

        raise ConnectionError(f"Failed to connect to {self.host} after {MAX_ATTEMPTS} attempts")

    # --- Polling periodico ---

    async def _async_update_data(self) -> dict:
        """Polling: connect → auth → status → disconnect."""
        try:
            data = await self.hass.async_add_executor_job(self._sync_update)
            self._persist_counter_from_data(data)
            return data["status"]
        except Exception as err:
            raise UpdateFailed(f"Update failed: {err}") from err

    def _sync_update(self) -> dict:
        with self._tcp_lock:
            # Grace period: dopo un comando recente, salta il poll per evitare
            # che una lettura intermedia sovrascriva lo stato appena applicato
            since_cmd = _time.monotonic() - self._last_command_time
            if self._last_command_time > 0 and since_cmd < COMMAND_GRACE_PERIOD:
                _LOGGER.debug(
                    "Skipping poll (%.1fs since last command, grace=%ss)",
                    since_cmd, COMMAND_GRACE_PERIOD,
                )
                return {
                    "status": dict(self.data or {}),
                    "counter": self.credentials.get("user_counter"),
                }
            client = self._connect_and_auth()
            try:
                # PING + poll per ClimaStateEvent (NO COMMIT per evitare
                # che stati SET pendenti vengano applicati dal firmware)
                client._last_clima_event = None
                client.ping()
                client._poll_for_events(2.0)
                if client._last_clima_event:
                    status = dict(client._last_clima_event)
                else:
                    status = client.get_status_safe()
                if status.get("scheduler"):
                    _LOGGER.warning(
                        "Device scheduler is active — this may cause "
                        "unexpected HVAC mode changes"
                    )
                # Traccia cambi di modo non richiesti dall'utente
                new_mode = status.get("mode")
                if (
                    self._last_known_mode is not None
                    and new_mode is not None
                    and new_mode != self._last_known_mode
                ):
                    since_cmd = _time.monotonic() - self._last_command_time
                    _LOGGER.warning(
                        "HVAC mode changed without user command: "
                        "%s -> %s (%.1fs since last command, "
                        "scheduler=%s, power=%s)",
                        self._last_known_mode, new_mode, since_cmd,
                        status.get("scheduler"), status.get("power"),
                    )
                self._last_known_mode = new_mode
                # Traccia transizioni power non richieste dall'utente
                new_power = status.get("power")
                if (
                    self._last_known_power is not None
                    and new_power is not None
                    and new_power != self._last_known_power
                ):
                    since_cmd = _time.monotonic() - self._last_command_time
                    if new_power and since_cmd > COMMAND_GRACE_PERIOD:
                        _LOGGER.warning(
                            "PHANTOM POWER ON: device turned ON without user "
                            "command (%.1fs since last cmd, scheduler=%s, "
                            "mode=%s). If scheduler is active, disable it "
                            "via the Scheduler switch.",
                            since_cmd, status.get("scheduler"),
                            status.get("mode"),
                        )
                    elif not new_power and since_cmd > COMMAND_GRACE_PERIOD:
                        _LOGGER.warning(
                            "Device turned OFF without user command "
                            "(%.1fs since last cmd, scheduler=%s)",
                            since_cmd, status.get("scheduler"),
                        )
                self._last_known_power = new_power
                _LOGGER.debug("poll data: %s", status)
                return {"status": status, "counter": client._user_counter}
            finally:
                client.disconnect()

    def _persist_counter_from_data(self, data: dict) -> None:
        """Persisti counter dal risultato sync (chiamato in event loop)."""
        new_counter = data.get("counter")
        if new_counter is not None:
            old_counter = self.credentials.get("user_counter")
            if new_counter != old_counter:
                _LOGGER.debug("Persisting user_counter: %s -> %s", old_counter, new_counter)
                self.credentials["user_counter"] = new_counter
                new_data = dict(self.entry.data)
                new_data["credentials"] = self.credentials
                self.hass.config_entries.async_update_entry(self.entry, data=new_data)

    # --- Comandi HVAC ---

    async def async_send_command(self, method_name: str, *args) -> bool:
        """Invia comando HVAC: connect → auth → comando → disconnect."""
        try:
            result = await self.hass.async_add_executor_job(
                self._sync_command, method_name, *args
            )
            return result
        except Exception as err:
            _LOGGER.warning("Command %s failed: %s", method_name, err)
            return False

    def _sync_command(self, method_name: str, *args) -> bool:
        with self._tcp_lock:
            client = self._connect_and_auth()
            try:
                method = getattr(client, method_name)
                result = method(*args)
                self._last_command_time = _time.monotonic()
                _LOGGER.debug("Command %s(%s) -> %s", method_name, args, result)
                if result and client._last_clima_event:
                    _LOGGER.debug("Post-commit device state: %s", client._last_clima_event)
                return result
            finally:
                client.disconnect()
