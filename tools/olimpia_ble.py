#!/usr/bin/env python3
"""
BLE client for Olimpia Splendid Unico.

Performs ECDH pairing via Bluetooth Low Energy and configures WiFi,
generating credential files for the Home Assistant integration.

Usage:
    # BLE scan (show all devices, highlight Olimpia ones)
    python3 olimpia_ble.py scan

    # Scan with name filter
    python3 olimpia_ble.py scan --name OL01

    # ECDH + PIN pairing only
    python3 olimpia_ble.py pair <BLE_ADDR> --pin 12345678

    # Full setup: pairing + WiFi config
    python3 olimpia_ble.py setup <BLE_ADDR> --pin 12345678 --ssid MyWiFi --password MyPass
"""

import asyncio
import argparse
import os
import sys
import struct
from typing import Optional

from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from olimpia.crypto import OlimpiaCrypto
from olimpia.tlv import TLV, AckResponse, hash_user_id, int_to_bigint_bytes, le_to_int
from olimpia.enums import Opcode
from olimpia.credentials import save_credentials, load_credentials


# --- Costanti GATT ---

SERVICE_UUID = "669a0c20-0008-f4bd-e611-f99570666da3"
WRITE_UUID   = "669a0c20-0008-f4bd-e611-f99571666da3"
NOTIFY_UUID  = "669a0c20-0008-f4bd-e611-f99572666da3"

BLE_MTU = 18  # 2 header + 16 payload utile
OLIMPIA_MARKER = bytes([0x1B, 0x2C])


# --- BLE Transport ---

class OlimpiaBLE:
    """Transport BLE per il protocollo TLV Olimpia."""

    def __init__(self, verbose: bool = False):
        self.client: Optional[BleakClient] = None
        self.verbose = verbose
        self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def _log(self, msg: str):
        if self.verbose:
            print(msg)

    # --- Scan ---

    @staticmethod
    async def scan(timeout: float = 10.0, name_filter: Optional[str] = None) -> list[dict]:
        """Scan BLE, ritorna lista di device trovati.

        Ogni entry: {address, name, rssi, is_olimpia, uid}
        """
        results = []
        seen = set()

        def callback(device: BLEDevice, adv: AdvertisementData):
            if device.address in seen:
                return
            seen.add(device.address)

            name = adv.local_name or device.name or ""
            if name_filter and name_filter.lower() not in name.lower():
                return

            entry = {
                'address': device.address,
                'name': name,
                'rssi': adv.rssi,
                'is_olimpia': False,
                'uid': None,
            }

            # Cerca manufacturer data con marker Olimpia
            for mfr_id, mfr_data in adv.manufacturer_data.items():
                if len(mfr_data) >= 10 and mfr_data[8:10] == OLIMPIA_MARKER:
                    entry['is_olimpia'] = True
                    entry['uid'] = mfr_data[0:8].decode('ascii', errors='replace')
                    break

            results.append(entry)

        scanner = BleakScanner(detection_callback=callback)
        print(f"[scan] Scanning BLE for {timeout}s...")
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()

        return results

    # --- Connect / Disconnect ---

    async def connect(self, address_or_device, timeout: float = 15.0):
        """Connetti al device BLE e abilita notify.

        address_or_device: stringa MAC oppure BLEDevice dallo scan.
        Passare un BLEDevice evita il re-scan interno di Bleak.
        """
        label = address_or_device.address if isinstance(address_or_device, BLEDevice) else address_or_device
        print(f"[ble] Connecting to {label}...")
        self.client = BleakClient(address_or_device, timeout=timeout)
        await self.client.connect()
        print(f"[ble] Connected! MTU: {self.client.mtu_size}")

        # Prova a ottenere il MTU reale (evita warning bleak)
        try:
            await self.client._backend._acquire_mtu()
        except Exception:
            pass
        print(f"[ble] MTU: {self.client.mtu_size}")

        await self.client.start_notify(NOTIFY_UUID, self._notify_handler)
        print(f"[ble] Notify enabled on {NOTIFY_UUID}")

        # L'app Java fa Thread.sleep(150) dopo il setup
        await asyncio.sleep(0.2)

    async def disconnect(self):
        """Disconnetti dal device BLE."""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            print("[ble] Disconnected")

    def _notify_handler(self, sender, data: bytearray):
        """Callback per notifiche BLE (risposte dal device)."""
        self._log(f"  RX [{len(data)}B]: {bytes(data).hex()}")
        self._rx_queue.put_nowait(bytes(data))

    # --- TLV Send/Receive ---

    async def _write_raw(self, data: bytes, retries: int = 5):
        """Scrivi dati grezzi sulla characteristic BLE (con retry su errori ATT)."""
        self._log(f"  TX [{len(data)}B]: {data.hex()}")
        for attempt in range(retries):
            try:
                await self.client.write_gatt_char(WRITE_UUID, data, response=True)
                return
            except Exception as e:
                if not self.client.is_connected:
                    raise  # Connessione persa, retry impossibile a questo livello
                err_str = str(e).lower()
                retryable = "0x0e" in err_str or "unlikely" in err_str
                if attempt < retries - 1 and retryable:
                    delay = 0.5 * (attempt + 1)
                    self._log(f"  TX retry {attempt+1}/{retries} (wait {delay:.1f}s): {e}")
                    await asyncio.sleep(delay)
                else:
                    raise

    def _drain_queue(self):
        """Svuota notifiche residue dalla queue."""
        drained = 0
        while not self._rx_queue.empty():
            try:
                self._rx_queue.get_nowait()
                drained += 1
            except asyncio.QueueEmpty:
                break
        if drained:
            self._log(f"  DRAIN: {drained} notifiche scartate")

    async def send_tlv(self, opcode: int, value: bytes = b"",
                       timeout: float = 10.0) -> Optional[TLV]:
        """Invia un TLV (con frammentazione applicativa se necessario) e attendi risposta.

        Formato frammento TX (da decompilato R/a.java:t()):
          TLV(type=opcode, length=chunk_size+2, value=[total_frags, frag_idx, chunk...])
        Ogni frammento è un TLV completo col suo opcode.
        Il device invia un ACK dopo ogni frammento; il prossimo si invia solo dopo l'ACK.

        Max TLV size per singola write: 20 byte (ATT payload con MTU 23).
        Se il value > 16 byte, frammenta (2B TLV header + 2B frag header + 16B chunk = 20B).
        """
        self._drain_queue()
        CHUNK_SIZE = 16  # f819q - 2 nel decompilato (18 - 2)

        if len(value) <= CHUNK_SIZE:
            # Singolo TLV — entra in 20B (2 header + max 18 value)
            tlv_bytes = TLV(type=opcode, length=len(value),
                           value=value or None).to_bytes()
            await self._write_raw(tlv_bytes)
        else:
            # Frammentazione applicativa: ogni frammento è un TLV completo
            total_frags = (len(value) + CHUNK_SIZE - 1) // CHUNK_SIZE
            for i in range(total_frags):
                offset = i * CHUNK_SIZE
                chunk = value[offset:offset + CHUNK_SIZE]
                frag_value = bytes([total_frags, i]) + chunk
                frag_tlv = TLV(type=opcode, length=len(frag_value),
                              value=frag_value).to_bytes()
                self._log(f"  TX FRAG [{i}/{total_frags}]: {frag_tlv.hex()}")
                await self._write_raw(frag_tlv)

                if i < total_frags - 1:
                    # Attendi ACK dal device prima di inviare il prossimo frammento
                    ack_data = await self._wait_notify(timeout)
                    if ack_data is None:
                        self._log(f"  TX FRAG ACK timeout dopo frammento {i}")
                        return None
                    self._log(f"  TX FRAG ACK: {ack_data.hex()}")

        # Attendi risposta finale
        return await self._recv_tlv(timeout)

    async def _wait_notify(self, timeout: float) -> Optional[bytes]:
        """Attendi una singola notifica BLE dalla queue."""
        try:
            return await asyncio.wait_for(self._rx_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            self._log("  RX timeout")
            return None

    async def _recv_tlv(self, timeout: float = 10.0) -> Optional[TLV]:
        """Attendi e riassembla una risposta TLV dal device (con gestione frammenti 0x7F)."""
        data = await self._wait_notify(timeout)
        if data is None or len(data) < 2:
            return None

        # Controlla se è un frammento (type 0x7F)
        if data[0] == 0x7F and len(data) >= 6:
            return await self._recv_fragmented(data, timeout)

        return TLV.from_bytes(data)

    async def _send_frag_ack(self):
        """Invia ACK per un frammento: TLV(0x00, 2, [0x7F, 0x00])."""
        ack = TLV(type=0x00, length=2, value=bytes([0x7F, 0x00])).to_bytes()
        self._log(f"  FACK TX: {ack.hex()}")
        await asyncio.sleep(0.08)  # delay per stabilità BLE (segnali deboli)
        await self._write_raw(ack)

    async def _recv_fragmented(self, first_data: bytes, timeout: float) -> Optional[TLV]:
        """Riassembla risposta frammentata (type 0x7F).

        Formato BLE: [0x7F] [len] [ackType] [ackResponse] [frameTotal] [frameIdx] [payload...]
        Nota: frameTotal PRIMA di frameIdx (come TCP).
        Via BLE il device invia tutti i frammenti consecutivamente (no ACK applicativo).
        """
        ack_type, ack_resp, total, idx, frag_data = self._parse_fragment(first_data)
        if total is None:
            return None

        self._log(f"  FRAG [{idx}/{total}]: type=0x{ack_type:02X} "
                  f"resp=0x{ack_resp:02X} data={len(frag_data)}B")

        fragments = {idx: frag_data}

        # Ricevi frammenti rimanenti (con ACK tra ogni frammento)
        for _ in range(total - 1):
            # Invia ACK per il frammento ricevuto
            await self._send_frag_ack()

            # Attendi prossimo frammento
            data = await self._wait_notify(timeout)
            if data is None or len(data) < 6 or data[0] != 0x7F:
                self._log(f"  FRAG timeout/errore: ricevuti {len(fragments)}/{total}")
                return None  # incompleto — il chiamante può ritentare

            _, _, _, next_idx, next_data = self._parse_fragment(data)
            self._log(f"  FRAG [{next_idx}/{total}]: data={len(next_data)}B")
            fragments[next_idx] = next_data

        # Riassembla in ordine
        payload = bytearray()
        for i in sorted(fragments.keys()):
            payload.extend(fragments[i])

        self._log(f"  FRAG riassemblato: {len(payload)}B da {len(fragments)} frame")

        # Costruisci TLV di risposta come AckResponse standard
        ack_value = bytes([ack_type, ack_resp]) + bytes(payload)
        return TLV(type=0x00, length=len(ack_value), value=ack_value)

    def _parse_fragment(self, data: bytes):
        """Parsa un frammento 0x7F. Returns (ack_type, ack_resp, total, idx, payload)."""
        if len(data) < 6 or data[0] != 0x7F:
            return None, None, None, None, b''
        frag_len = data[1]
        ack_type = data[2]
        ack_resp = data[3]
        frame_total = data[4]  # total PRIMA di idx (come TCP)
        frame_idx = data[5]
        frag_data = data[6:6 + frag_len - 4] if frag_len > 4 else b''
        return ack_type, ack_resp, frame_total, frame_idx, frag_data

    # --- Encrypted TLV ---

    # Max ATT payload = MTU(23) - 3 = 20 byte
    # Encrypted frame: [type|0x80(1)] [orig_len(1)] [ct(orig_len)] [tag(6)] [counter(4)]
    # → orig_len max = 20 - 12 = 8 byte
    # Con frag header [total, idx]: chunk max = 8 - 2 = 6 byte
    ENC_MAX_VALUE = 8     # max valore plaintext in un frame cifrato BLE
    ENC_CHUNK_SIZE = 6    # max chunk di dati originali con frag header

    def _build_encrypted_frame(self, opcode: int, value: bytes,
                                crypto: OlimpiaCrypto,
                                user_hash: bytes, user_counter: int,
                                device_uid: bytes) -> bytes:
        """Costruisci un singolo frame cifrato BLE."""
        ct, tag, counter_bytes = crypto.encrypt(
            opcode, value or None, user_hash, user_counter, device_uid
        )
        raw = bytearray()
        raw.append(opcode | 0x80)
        raw.append(len(value) if value else 0)
        raw.extend(ct + tag)
        raw.extend(counter_bytes)
        return bytes(raw)

    async def send_encrypted_tlv(self, opcode: int, value: bytes,
                                 crypto: OlimpiaCrypto,
                                 user_hash: bytes, user_counter: int,
                                 device_uid: bytes,
                                 timeout: float = 10.0) -> Optional[TLV]:
        """Invia un TLV cifrato AES-GCM e attendi risposta.

        Se il valore è > ENC_MAX_VALUE (8B), frammenta con l'algoritmo
        identico a quello Java (R/a.java t()):
        - iCeil = int(ceil(len/chunk_size)) con DIVISIONE INTERA Java
        - Primo frammento: chunk_size byte
        - Ultimo frammento: byte rimanenti (può essere > chunk_size)
        Ogni frammento viene cifrato indipendentemente.
        """
        self._drain_queue()

        if len(value) <= self.ENC_MAX_VALUE:
            # Singolo frame cifrato
            frame = self._build_encrypted_frame(
                opcode, value, crypto, user_hash, user_counter, device_uid)
            self._log(f"  TX(enc) [{len(frame)}B]: {frame.hex()}")
            await self._write_raw(frame)
        else:
            # Frammentazione: cifra ogni chunk da max ENC_CHUNK_SIZE byte
            total_frags = (len(value) + self.ENC_CHUNK_SIZE - 1) // self.ENC_CHUNK_SIZE
            for i in range(total_frags):
                offset = i * self.ENC_CHUNK_SIZE
                chunk = value[offset:offset + self.ENC_CHUNK_SIZE]
                frag_value = bytes([total_frags, i]) + chunk

                frame = self._build_encrypted_frame(
                    opcode, frag_value, crypto, user_hash, user_counter, device_uid)
                self._log(f"  TX(enc) FRAG [{i}/{total_frags}]: [{len(frame)}B] {frame.hex()}")
                await self._write_raw(frame)

                if i < total_frags - 1:
                    # Attendi ACK dal device
                    ack_data = await self._wait_notify(timeout)
                    if ack_data is None:
                        self._log(f"  TX(enc) FRAG ACK timeout dopo frammento {i}")
                        return None
                    self._log(f"  TX(enc) FRAG ACK: {ack_data.hex()}")

        # Attendi risposta finale
        return await self._recv_encrypted_tlv(crypto, user_hash, user_counter,
                                               device_uid, timeout)

    def _decrypt_raw_frame(self, raw: bytes, crypto: OlimpiaCrypto,
                           user_hash: bytes, user_counter: int,
                           device_uid: bytes) -> Optional[tuple]:
        """Decripta un singolo frame cifrato BLE.
        Returns (orig_type, plaintext) o None se fallisce."""
        if len(raw) < 2:
            return None

        enc_type = raw[0]
        orig_type = enc_type & 0x7F
        orig_length = raw[1]

        ct_and_tag_len = orig_length + 6
        min_len = 2 + ct_and_tag_len

        if len(raw) < min_len:
            self._log(f"  RX(enc) troppo corto: {len(raw)}B, attesi {min_len}B")
            return None

        ct_and_tag = raw[2:2 + ct_and_tag_len]
        remaining = raw[2 + ct_and_tag_len:]
        counter_bytes = (remaining + b'\x00\x00\x00\x00')[:4]
        device_counter = le_to_int(counter_bytes)

        ct = ct_and_tag[:orig_length] if orig_length > 0 else b''
        tag = ct_and_tag[orig_length:orig_length + 6]

        self._log(f"  RX(enc) type=0x{orig_type:02X} len={orig_length} "
                  f"dev_counter={device_counter} tag={tag.hex()}")

        crypto.counter += 1
        if device_counter >= crypto.counter:
            crypto.counter = device_counter

        plaintext = crypto.decrypt(
            orig_type, ct, tag, device_counter,
            user_hash, user_counter, device_uid
        )

        if plaintext is None:
            self._log("  RX(enc) decrypt FAILED")
            return None

        self._log(f"  RX(enc) decrypted: type=0x{orig_type:02X} pt={plaintext.hex()}")
        return (orig_type, plaintext)

    async def _recv_encrypted_tlv(self, crypto: OlimpiaCrypto,
                                   user_hash: bytes, user_counter: int,
                                   device_uid: bytes,
                                   timeout: float) -> Optional[TLV]:
        """Attendi e decripta una risposta cifrata dal device.
        Gestisce frammenti cifrati (orig_type=0x7F): ogni frammento è cifrato
        indipendentemente, con ACK plaintext tra ciascuno."""
        raw = await self._wait_notify(timeout)
        if raw is None:
            self._log("  RX(enc) timeout")
            return None

        result = self._decrypt_raw_frame(raw, crypto, user_hash,
                                          user_counter, device_uid)
        if result is None:
            return None

        orig_type, plaintext = result

        # Frammento cifrato: orig_type=0x7F
        # Plaintext: [ackType(1)] [ackResponse(1)] [totalFrags(1)] [frameIdx(1)] [payload...]
        if orig_type == 0x7F and len(plaintext) >= 4:
            return await self._recv_encrypted_fragments(
                plaintext, crypto, user_hash, user_counter, device_uid, timeout)

        # Risposta singola (non frammentata)
        if len(plaintext) >= 2:
            ack_value = bytes([plaintext[0], plaintext[1]]) + plaintext[2:]
            return TLV(type=0x00, length=len(ack_value), value=ack_value)
        elif len(plaintext) == 0:
            return TLV(type=orig_type, length=0, value=None)
        return TLV(type=0x00, length=len(plaintext), value=plaintext)

    async def _recv_encrypted_fragments(self, first_plaintext: bytes,
                                         crypto: OlimpiaCrypto,
                                         user_hash: bytes, user_counter: int,
                                         device_uid: bytes,
                                         timeout: float) -> Optional[TLV]:
        """Riassembla frammenti dopo una risposta cifrata con orig_type=0x7F.
        Il PRIMO frammento arriva cifrato (0xFF), i successivi come PLAINTEXT (0x7F).
        Tra un frammento e l'altro si invia ACK plaintext [0x00, 0x02, 0x7F, 0x00].
        """
        ack_type = first_plaintext[0]
        ack_resp = first_plaintext[1]
        total_frags = first_plaintext[2]
        frame_idx = first_plaintext[3]
        payload = first_plaintext[4:]

        self._log(f"  ENC_FRAG [{frame_idx}/{total_frags}]: ackType=0x{ack_type:02X} "
                  f"ackResp=0x{ack_resp:02X} payload={len(payload)}B")

        fragments = {frame_idx: payload}

        for _ in range(total_frags - 1):
            # Invia ACK plaintext per il frammento ricevuto
            await self._send_frag_ack()

            # Attendi prossimo frammento (PLAINTEXT 0x7F, non cifrato)
            raw = await self._wait_notify(timeout)
            if raw is None:
                self._log(f"  ENC_FRAG timeout: ricevuti {len(fragments)}/{total_frags}")
                break

            if len(raw) < 6:
                self._log(f"  ENC_FRAG troppo corto: {len(raw)}B")
                break

            # Controlla se cifrato (0x80 bit) o plaintext
            if raw[0] & 0x80:
                # Cifrato — decripta
                result = self._decrypt_raw_frame(raw, crypto, user_hash,
                                                  user_counter, device_uid)
                if result is None:
                    self._log(f"  ENC_FRAG decrypt failed: ricevuti {len(fragments)}/{total_frags}")
                    break
                _, frag_pt = result
                if len(frag_pt) < 4:
                    self._log(f"  ENC_FRAG payload troppo corto: {len(frag_pt)}B")
                    break
                f_ack_type, f_ack_resp, f_total, f_idx = frag_pt[0], frag_pt[1], frag_pt[2], frag_pt[3]
                f_payload = frag_pt[4:]
            else:
                # Plaintext 0x7F — usa _parse_fragment esistente
                f_ack_type, f_ack_resp, f_total, f_idx, f_payload = self._parse_fragment(raw)
                if f_total is None:
                    self._log(f"  ENC_FRAG parse failed: {raw[:10].hex()}")
                    break

            self._log(f"  ENC_FRAG [{f_idx}/{f_total}]: payload={len(f_payload)}B")
            fragments[f_idx] = f_payload
            ack_type = f_ack_type
            ack_resp = f_ack_resp

        # ACK anche per l'ultimo frammento (come fa Java)
        await self._send_frag_ack()

        # Riassembla payload in ordine di frameIdx
        full_payload = bytearray()
        for i in sorted(fragments.keys()):
            full_payload.extend(fragments[i])

        self._log(f"  ENC_FRAG riassemblato: {len(full_payload)}B da "
                  f"{len(fragments)}/{total_frags} frammenti, "
                  f"ackType=0x{ack_type:02X} ackResp=0x{ack_resp:02X}")

        # Costruisci TLV come Java: [ackType, ackResponse, payload...]
        ack_value = bytes([ack_type, ack_resp]) + bytes(full_payload)
        return TLV(type=0x00, length=len(ack_value), value=ack_value)

    # --- Comandi di alto livello ---

    async def send_command(self, opcode: int, value: bytes = b"",
                           timeout: float = 10.0,
                           retries: int = 1) -> Optional[AckResponse]:
        """Invia un comando TLV plaintext e ritorna AckResponse.

        retries: numero di tentativi (>1 utile per comandi frammentati su segnale debole).
        """
        for attempt in range(retries):
            self._drain_queue()
            tlv = await self.send_tlv(opcode, value, timeout)
            if tlv is not None:
                return AckResponse.from_tlv(tlv)
            if attempt < retries - 1:
                delay = 1.0 + attempt * 0.5
                print(f"  [retry {attempt+1}/{retries}] opcode 0x{opcode:02X}, "
                      f"waiting {delay:.1f}s...")
                await asyncio.sleep(delay)
                # Drain eventuali notifiche residue dal tentativo precedente
                self._drain_queue()
        return None

    async def send_encrypted_command(self, opcode: int, value: bytes,
                                     crypto: OlimpiaCrypto,
                                     user_hash: bytes, user_counter: int,
                                     device_uid: bytes,
                                     timeout: float = 10.0) -> Optional[AckResponse]:
        """Invia un comando TLV cifrato e ritorna AckResponse."""
        tlv = await self.send_encrypted_tlv(
            opcode, value, crypto, user_hash, user_counter, device_uid, timeout
        )
        if tlv is None:
            return None
        return AckResponse.from_tlv(tlv)


# --- Pairing ---

async def ble_pair(ble: OlimpiaBLE, pin: int,
                   user_id: str = "olimpia-python",
                   device_uid_override: Optional[str] = None) -> bool:
    """Pairing ECDH completo via BLE (identico al TCP, ma su transport BLE)."""
    crypto = OlimpiaCrypto()
    user_hash = hash_user_id(user_id)
    user_counter = 0

    print(f"[pair] userId: {user_id}")
    print(f"[pair] hash: {user_hash.hex()}")

    # 1. GET_CERTIFICATE (0x35) — 30 frammenti, retry su segnale debole
    print("[pair] 1/8 GET_CERTIFICATE...")
    ack = await ble.send_command(Opcode.GET_CERTIFICATE, timeout=15.0, retries=5)
    if not ack or not ack.success:
        print(f"[pair] FAIL: {ack}")
        return False
    cert_data = ack.ack_data
    print(f"[pair] Certificate: {len(cert_data)}B")

    # Estrai device UID dal CN del certificato
    from cryptography import x509
    cert = x509.load_der_x509_certificate(cert_data)
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    print(f"[pair] Certificate CN: {cn}")

    if device_uid_override:
        uid_str = device_uid_override
    else:
        uid_str = f"{int(cn):08d}"
    device_uid = uid_str.encode('utf-8')
    print(f"[pair] Device UID (AAD): {uid_str}")

    # 2. INIT_DH (0x34) — invio nostra pubkey (64B)
    print("[pair] 2/8 INIT_DH (sending pubkey)...")
    crypto.generate_keypair()
    pubkey = crypto.get_pubkey_bytes()
    ack = await ble.send_command(Opcode.INIT_DH, pubkey, timeout=15.0)
    if not ack or not ack.success:
        print(f"[pair] FAIL: {ack}")
        return False
    print("[pair] DH init OK")

    # 3. GET_DH_PUBKEY (0x37)
    print("[pair] 3/8 GET_DH_PUBKEY...")
    ack = await ble.send_command(Opcode.GET_DH_PUBKEY, timeout=10.0)
    if not ack or not ack.success or not ack.ack_data:
        print(f"[pair] FAIL: {ack}")
        return False
    crypto.set_device_pubkey(ack.ack_data)
    crypto.compute_shared_secret()
    crypto.compute_ltk()
    print("[pair] Shared secret + LTK computed")

    # 4. GET_SIGNATURE (0x36)
    print("[pair] 4/8 GET_SIGNATURE...")
    ack = await ble.send_command(Opcode.GET_SIGNATURE, timeout=15.0)
    if not ack or not ack.success or not ack.ack_data:
        print(f"[pair] FAIL: {ack}")
        return False
    print(f"[pair] Signature: {len(ack.ack_data)}B")

    # 5. SEND_HASH_USERID (0x44)
    print("[pair] 5/8 SEND_HASH_USERID...")
    ack = await ble.send_command(Opcode.SEND_HASH_USERID, user_hash)
    if not ack or not ack.success:
        print(f"[pair] FAIL: {ack}")
        return False

    # 6. SEND_USER_COUNTER (0x45)
    print("[pair] 6/8 SEND_USER_COUNTER...")
    ack = await ble.send_command(Opcode.SEND_USER_COUNTER, bytes([user_counter]))
    if not ack or not ack.success:
        print(f"[pair] FAIL: {ack}")
        return False
    if ack.ack_data:
        dev_counter = le_to_int(ack.ack_data)
        user_counter = dev_counter
        print(f"[pair] Device counter: {dev_counter}")

    # 7. SEND_SESSION_RANDOM (0x38)
    print("[pair] 7/8 SEND_SESSION_RANDOM...")
    rnd_host = os.urandom(8)
    ack = await ble.send_command(Opcode.SEND_SESSION_RANDOM, rnd_host)
    if not ack or not ack.success or not ack.ack_data:
        print(f"[pair] FAIL: {ack}")
        return False
    rnd_device = ack.ack_data
    crypto.compute_session_key(rnd_host, rnd_device)
    print("[pair] Session key computed")

    # 8. SEND_IV_HEAD (0x39)
    print("[pair] 8/8 SEND_IV_HEAD...")
    iv_head = crypto.generate_iv_head()
    ack = await ble.send_command(Opcode.SEND_IV_HEAD, iv_head)
    if not ack or not ack.success:
        print(f"[pair] FAIL: {ack}")
        return False

    print("[pair] AES-GCM encryption active!")

    # 9. SEND_HASH_USERID (encrypted)
    print("[pair] 9/10 SEND_HASH_USERID (encrypted)...")
    ack = await ble.send_encrypted_command(
        Opcode.SEND_HASH_USERID, user_hash,
        crypto, user_hash, user_counter, device_uid
    )
    if not ack or not ack.success:
        print(f"[pair] WARN: {ack}")

    # 10. SEND_USER_COUNTER (encrypted)
    print("[pair] 10/10 SEND_USER_COUNTER (encrypted)...")
    ack = await ble.send_encrypted_command(
        Opcode.SEND_USER_COUNTER, bytes([user_counter]),
        crypto, user_hash, user_counter, device_uid
    )
    if ack and ack.success and ack.ack_data:
        final_counter = le_to_int(ack.ack_data)
        print(f"[pair] Final counter: {final_counter}")

    # 11. SEND_PIN (encrypted) — persiste l'utente
    # Delay prima di SEND_PIN per dare tempo al device
    await asyncio.sleep(1.0)
    print(f"[pair] 11/11 SEND_PIN (encrypted) pin={pin}...")
    pin_bytes = int_to_bigint_bytes(pin)
    ack = await ble.send_encrypted_command(
        Opcode.SEND_PIN, pin_bytes,
        crypto, user_hash, user_counter, device_uid,
        timeout=45.0
    )
    if not ack:
        print("[pair] SEND_PIN timeout (35s)")
        return False
    if not ack.success:
        print(f"[pair] SEND_PIN error: {ack}")
        return False

    sig = ack.ack_data
    print(f"[pair] PIN accepted! Signature: {len(sig) if sig else 0}B")

    # Salva credenziali (per il client TCP successivo)
    # L'host è sconosciuto via BLE — verrà aggiornato dopo il WiFi setup
    save_credentials("ble-pending", user_id, user_hash,
                     user_counter, crypto, device_uid)

    print("[pair] BLE PAIRING COMPLETE!")
    return True


# --- WiFi Config ---

# Opcode corretti dal decompilato (diversi dalla Opcode class TCP):
#   0x03 = SET_NAME (U/?.java — device name, 1-6 char)
#   0x05 = SET_SSID (U/d0.java — WiFi SSID)
#   0x07 = SET_PASSWORD (U/c0.java — WiFi password)
BLE_SET_NAME = 0x03
BLE_SET_SSID = 0x05
BLE_SET_PASSWORD = 0x07
BLE_GET_MAC = 0x08  # Il device si connette al WiFi e ritorna la MAC (timeout 30s)


async def ble_set_name(ble: OlimpiaBLE, name: str,
                       crypto: OlimpiaCrypto, user_hash: bytes,
                       user_counter: int, device_uid: bytes) -> bool:
    """Imposta il nome del device (1-6 char), opcode 0x03."""
    name = name[:6]
    print(f"[wifi] SET_NAME (0x03): '{name}'")
    ack = await ble.send_encrypted_command(
        BLE_SET_NAME, name.encode('utf-8'),
        crypto, user_hash, user_counter, device_uid
    )
    if not ack or not ack.success:
        print(f"[wifi] SET_NAME failed: {ack}")
        return False
    print("[wifi] Name set")
    return True


async def ble_set_wifi(ble: OlimpiaBLE, ssid: str, password: str,
                       crypto: OlimpiaCrypto, user_hash: bytes,
                       user_counter: int, device_uid: bytes) -> bool:
    """Configura WiFi: GET_CONN_STATUS + SET_SSID (0x05) + SET_PASSWORD (0x07)."""
    # GET_CONN_STATUS (0x25) — come fa l'app prima del WiFi config
    print("[wifi] GET_CONN_STATUS (0x25)...")
    ack = await ble.send_encrypted_command(
        0x25, b"",
        crypto, user_hash, user_counter, device_uid
    )
    if ack:
        status = ack.ack_data[0] if ack.ack_data else 0
        print(f"[wifi] Current status: {'connected' if status == 1 else 'not connected'} (0x{status:02X})")

    print(f"[wifi] SET_SSID (0x05): '{ssid}'")
    ack = await ble.send_encrypted_command(
        BLE_SET_SSID, ssid.encode('utf-8'),
        crypto, user_hash, user_counter, device_uid
    )
    if not ack or not ack.success:
        print(f"[wifi] SET_SSID failed: {ack}")
        return False
    print("[wifi] SSID set")

    print(f"[wifi] SET_PASSWORD (0x07): {'*' * len(password)}")
    ack = await ble.send_encrypted_command(
        BLE_SET_PASSWORD, password.encode('utf-8'),
        crypto, user_hash, user_counter, device_uid
    )
    if not ack or not ack.success:
        print(f"[wifi] SET_PASSWORD failed: {ack}")
        return False
    print("[wifi] Password set")
    # Delay per dare tempo al device di processare prima di GET_MAC
    await asyncio.sleep(2.0)
    return True


async def ble_wait_wifi_mac(ble: OlimpiaBLE,
                            crypto: OlimpiaCrypto, user_hash: bytes,
                            user_counter: int, device_uid: bytes,
                            timeout: float = 30.0,
                            max_attempts: int = 3) -> Optional[str]:
    """Invia GET_MAC (0x08) e attendi che il device si connetta al WiFi.

    Il device tenta la connessione WiFi e risponde con la propria MAC/IP
    quando è connesso. Timeout lungo (30s) come nell'app Java (C0219b).
    Ritorna la MAC/IP come stringa, o None se fallisce.
    """
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            print(f"[wifi] Waiting 5s before attempt {attempt}...")
            await asyncio.sleep(5.0)

        print(f"[wifi] GET_MAC (0x08) attempt {attempt}/{max_attempts} "
              f"(timeout {timeout}s)...")
        ack = await ble.send_encrypted_command(
            BLE_GET_MAC, b"",
            crypto, user_hash, user_counter, device_uid,
            timeout=timeout
        )
        if ack:
            print(f"[wifi] Response: cmd=0x{ack.ack_type:02X} "
                  f"status={'OK' if ack.success else 'ERR'} "
                  f"data={ack.ack_data.hex() if ack.ack_data else 'None'}")

            if ack.success and ack.ack_data:
                result = ack.ack_data.decode('utf-8', errors='replace').strip('\x00').strip()
                if result:
                    print(f"[wifi] WiFi connected! Response: {result}")
                    return result
        else:
            print(f"[wifi] Attempt {attempt}: no response")

    print("[wifi] WiFi not connected after all attempts")
    return None


# --- Setup completo ---

async def ble_full_setup(ble: OlimpiaBLE, pin: int, ssid: str, password: str,
                         user_id: str = "olimpia-python",
                         name: Optional[str] = None) -> bool:
    """Setup completo: pairing ECDH + PIN + WiFi config."""

    # Pairing (riusa la funzione che salva le credenziali)
    if not await ble_pair(ble, pin, user_id):
        return False

    # Carica le credenziali appena salvate per i comandi cifrati
    creds = load_credentials("ble-pending")
    if not creds:
        print("[setup] ERROR: credentials not found after pairing")
        return False

    crypto = OlimpiaCrypto()
    crypto_data = creds['crypto']
    crypto.shared_secret = bytes.fromhex(crypto_data['shared_secret'])
    crypto.ltk = bytes.fromhex(crypto_data['ltk'])
    crypto.session_key = bytes.fromhex(crypto_data['session_key'])
    crypto.iv_head = bytes.fromhex(crypto_data['iv_head'])
    crypto.rnd_host = bytes.fromhex(crypto_data['rnd_host'])
    crypto.rnd_device = bytes.fromhex(crypto_data['rnd_device'])
    crypto.counter = crypto_data['counter']

    user_hash = bytes.fromhex(creds['user_hash'])
    user_counter = creds['user_counter']
    device_uid = bytes.fromhex(creds['device_uid']) if creds.get('device_uid') else b'00014980'

    # SET_NAME (opzionale)
    if name:
        await ble_set_name(ble, name, crypto, user_hash, user_counter, device_uid)

    # WiFi config
    if not await ble_set_wifi(ble, ssid, password, crypto, user_hash, user_counter, device_uid):
        return False

    # GET_MAC — il device si connette al WiFi e ritorna la MAC (timeout 30s)
    mac = await ble_wait_wifi_mac(ble, crypto, user_hash, user_counter, device_uid)

    if mac:
        # WiFi connesso — ottieni l'IP
        ack = await ble.send_encrypted_command(
            Opcode.GET_IP, b"",
            crypto, user_hash, user_counter, device_uid
        )
        if ack and ack.success and ack.ack_data:
            ip = ack.ack_data.decode('utf-8', errors='replace').strip('\x00')
            print(f"[setup] Device IP: {ip}")
            save_credentials(ip, user_id, user_hash, user_counter, crypto, device_uid)
            print(f"[setup] Credentials saved for {ip}")
            print(f"[setup] Credential file: ~/.olimpia/{ip}.json")
            print(f"[setup] You can now import this into Home Assistant (Manual IP setup).")
        else:
            print("[setup] Could not get device IP — credentials saved as 'ble-pending'")
            print("[setup] After finding the IP, rename ~/.olimpia/ble-pending.json → ~/.olimpia/<IP>.json")

        print("[setup] SETUP COMPLETE!")
        return True

    print("[setup] Partial setup — WiFi not connected")
    return False


# --- CLI ---

async def _resolve_device(address: str, timeout: float = 10.0) -> BLEDevice:
    """Scan BLE e ritorna il BLEDevice corrispondente all'indirizzo.

    Passare un BLEDevice a BleakClient evita il re-scan interno,
    risolvendo il problema di connessione con segnale debole.
    """
    print(f"[ble] Scanning for {address}...")
    device = await BleakScanner.find_device_by_address(address, timeout=timeout)
    if device is None:
        raise RuntimeError(f"Device {address} not found during scan (timeout {timeout}s)")
    print(f"[ble] Device found: {device.name or 'N/A'}")
    return device


async def cmd_scan(args):
    results = await OlimpiaBLE.scan(
        timeout=args.timeout,
        name_filter=args.name,
    )
    if not results:
        print("No BLE devices found.")
        return

    print(f"\n{'Address':<20} {'Name':<15} {'RSSI':>5}  {'Info'}")
    print("-" * 65)
    for d in sorted(results, key=lambda x: x['rssi'], reverse=True):
        info = ""
        if d['is_olimpia']:
            info = f"*** OLIMPIA UID={d['uid']} ***"
        print(f"{d['address']:<20} {d['name']:<15} {d['rssi']:>5}  {info}")


async def cmd_pair(args, max_attempts: int = 3):
    for attempt in range(max_attempts):
        device = await _resolve_device(args.address)
        ble = OlimpiaBLE(verbose=args.verbose)
        try:
            await ble.connect(device)
            await ble_pair(ble, args.pin, args.user_id)
            return
        except Exception as e:
            err = str(e).lower()
            retryable = any(k in err for k in ("0x0e", "unlikely", "not found",
                                                "not connected", "service discovery"))
            if attempt < max_attempts - 1 and retryable:
                print(f"\n[pair] BLE error: {e}")
                print(f"[pair] Attempt {attempt+2}/{max_attempts} in 3s...")
                await asyncio.sleep(3)
            else:
                raise
        finally:
            await ble.disconnect()


async def cmd_setup(args, max_attempts: int = 3):
    for attempt in range(max_attempts):
        device = await _resolve_device(args.address)
        ble = OlimpiaBLE(verbose=args.verbose)
        try:
            await ble.connect(device)
            await ble_full_setup(
                ble, args.pin, args.ssid, args.password,
                user_id=args.user_id,
                name=args.name,
            )
            return  # successo
        except Exception as e:
            err = str(e).lower()
            retryable = any(k in err for k in ("0x0e", "unlikely", "not found",
                                                "not connected", "service discovery"))
            if attempt < max_attempts - 1 and retryable:
                print(f"\n[setup] BLE error: {e}")
                print(f"[setup] Attempt {attempt+2}/{max_attempts} in 3s...")
                await asyncio.sleep(3)
            else:
                raise
        finally:
            await ble.disconnect()


async def cmd_wifi(args):
    """WiFi config su sessione esistente (pairing già fatto)."""
    device = await _resolve_device(args.address)
    ble = OlimpiaBLE(verbose=args.verbose)
    try:
        await ble.connect(device)

        # Rifare pairing per creare sessione crittografata
        if not await ble_pair(ble, args.pin, args.user_id):
            return

        creds = load_credentials("ble-pending")
        if not creds:
            print("[wifi] Credentials not found")
            return

        crypto = OlimpiaCrypto()
        cd = creds['crypto']
        crypto.shared_secret = bytes.fromhex(cd['shared_secret'])
        crypto.ltk = bytes.fromhex(cd['ltk'])
        crypto.session_key = bytes.fromhex(cd['session_key'])
        crypto.iv_head = bytes.fromhex(cd['iv_head'])
        crypto.rnd_host = bytes.fromhex(cd['rnd_host'])
        crypto.rnd_device = bytes.fromhex(cd['rnd_device'])
        crypto.counter = cd['counter']

        user_hash = bytes.fromhex(creds['user_hash'])
        user_counter = creds['user_counter']
        device_uid = bytes.fromhex(creds['device_uid']) if creds.get('device_uid') else b'00014980'

        if not await ble_set_wifi(ble, args.ssid, args.password,
                                   crypto, user_hash, user_counter, device_uid):
            return

        mac = await ble_wait_wifi_mac(ble, crypto, user_hash, user_counter, device_uid)
        if mac:
            ack = await ble.send_encrypted_command(
                Opcode.GET_IP, b"",
                crypto, user_hash, user_counter, device_uid
            )
            if ack and ack.success and ack.ack_data:
                ip = ack.ack_data.decode('utf-8', errors='replace').strip('\x00')
                print(f"[wifi] IP: {ip}")
                save_credentials(ip, args.user_id, user_hash, user_counter, crypto, device_uid)
                print(f"[wifi] Credentials saved for {ip}")
        else:
            print("[wifi] WiFi not connected")
    finally:
        await ble.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="BLE pairing tool for Olimpia Splendid Unico"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan for BLE devices")
    p_scan.add_argument("--name", help="Filter by name (e.g. OL01)")
    p_scan.add_argument("--timeout", type=float, default=10.0,
                        help="Scan duration in seconds (default: 10)")

    # pair
    p_pair = sub.add_parser("pair", help="ECDH + PIN pairing only")
    p_pair.add_argument("address", help="BLE MAC address of the device")
    p_pair.add_argument("--pin", type=int, required=True, help="Device PIN")
    p_pair.add_argument("--user-id", default="olimpia-python",
                        help="User ID (default: olimpia-python)")

    # setup
    p_setup = sub.add_parser("setup", help="Full setup: pairing + WiFi config")
    p_setup.add_argument("address", help="BLE MAC address of the device")
    p_setup.add_argument("--pin", type=int, required=True, help="Device PIN")
    p_setup.add_argument("--ssid", required=True, help="WiFi SSID")
    p_setup.add_argument("--password", required=True, help="WiFi password")
    p_setup.add_argument("--name", help="Device name (1-6 chars)")
    p_setup.add_argument("--user-id", default="olimpia-python",
                        help="User ID (default: olimpia-python)")

    # wifi
    p_wifi = sub.add_parser("wifi", help="WiFi config (performs pairing for encrypted session)")
    p_wifi.add_argument("address", help="BLE MAC address of the device")
    p_wifi.add_argument("--pin", type=int, required=True, help="Device PIN")
    p_wifi.add_argument("--ssid", required=True, help="WiFi SSID")
    p_wifi.add_argument("--password", required=True, help="WiFi password")
    p_wifi.add_argument("--user-id", default="olimpia-python",
                        help="User ID (default: olimpia-python)")

    args = parser.parse_args()

    if args.command == "scan":
        asyncio.run(cmd_scan(args))
    elif args.command == "pair":
        asyncio.run(cmd_pair(args))
    elif args.command == "setup":
        asyncio.run(cmd_setup(args))
    elif args.command == "wifi":
        asyncio.run(cmd_wifi(args))


if __name__ == "__main__":
    main()
