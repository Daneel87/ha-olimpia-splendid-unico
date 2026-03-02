"""DataUpdateCoordinator per Olimpia Splendid Unico."""

import logging
import threading
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SCAN_INTERVAL
from .olimpia.client import OlimpiaClient

_LOGGER = logging.getLogger(__name__)

MAX_ATTEMPTS = 3
RETRY_DELAYS = [3, 5]  # secondi tra tentativi


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
            client = self._connect_and_auth()
            try:
                # Refresh + poll per ClimaStateEvent
                client._last_clima_event = None
                client.refresh()
                client._poll_for_events(2.0)
                if client._last_clima_event:
                    status = dict(client._last_clima_event)
                else:
                    status = client.get_status_safe()
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
                return result
            finally:
                client.disconnect()
