"""Client TCP per Olimpia Splendid Unico."""

import hashlib
import math
import os
import socket
import threading
import time
from typing import Optional, Tuple

from .enums import Mode, Fan, Opcode
from .tlv import TLV, AckResponse, int_to_le, le_to_int, be_to_short, int_to_bigint_bytes, hash_user_id
from .crypto import OlimpiaCrypto
from .credentials import save_credentials, load_credentials


class OlimpiaClient:
    PORT = 2000
    READ_SIZE = 40
    DEFAULT_TIMEOUT = 6.0
    FRAME_SIZE = 18

    def __init__(self, host: str, port: int = PORT, hex_encoding: bool = True):
        self.host = host
        self.port = port
        self.hex_encoding = hex_encoding
        self._sock: Optional[socket.socket] = None
        self._crypto: Optional[OlimpiaCrypto] = None
        self._encrypted = False
        self._user_hash: Optional[bytes] = None
        self._user_counter: int = 0
        self._device_uid: Optional[bytes] = None
        self._last_clima_event: Optional[dict] = None
        self._crypto_ok = False
        self._recv_buf = bytearray()
        self._cmd_lock = threading.Lock()
        self._event_callbacks: list = []
        self.verbose = False

    _last_disconnect_time: float = 0

    # --- Connessione ---

    def connect(self, timeout: float = 8.0):
        elapsed = time.monotonic() - OlimpiaClient._last_disconnect_time
        if OlimpiaClient._last_disconnect_time > 0 and elapsed < 2.0:
            wait = 2.0 - elapsed
            self._log(f"  Rate limit: attendo {wait:.1f}s...")
            time.sleep(wait)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(timeout)
        self._sock.connect((self.host, self.port))

    def disconnect(self):
        if self._sock:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._recv_buf.clear()
            OlimpiaClient._last_disconnect_time = time.monotonic()

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def _log(self, msg: str):
        if self.verbose:
            import logging
            logging.getLogger(__name__).debug(msg)

    def _log_warn(self, msg: str):
        import logging
        logging.getLogger(__name__).warning(msg)

    # --- Trasporto ---

    def _send_tlv(self, tlv: TLV):
        if not self._sock:
            raise ConnectionError("Non connesso")
        if self._encrypted and self._crypto:
            self._send_encrypted_tlv(tlv)
        else:
            data = tlv.to_wire(self.hex_encoding)
            self._log(f"  TX [{len(data)}B]: {data.hex()}")
            self._sock.sendall(data)

    def _send_encrypted_tlv(self, tlv: TLV):
        ct, tag, counter_bytes = self._crypto.encrypt(
            tlv.type, tlv.value, self._user_hash, self._user_counter,
            self._device_uid
        )
        raw = bytearray()
        raw.append(tlv.type | 0x80)
        raw.append(tlv.length)
        raw.extend(ct + tag)
        raw.extend(counter_bytes)
        if self.hex_encoding:
            wire = bytes(raw).hex().encode('ascii')
        else:
            wire = bytes(raw)
        self._log(f"  TX(enc) [{len(wire)}B]: {wire.hex()}")
        self._sock.sendall(wire)

    def _recv_raw(self, timeout: Optional[float] = None) -> Optional[bytes]:
        if not self._sock:
            raise ConnectionError("Non connesso")
        old_timeout = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            data = self._sock.recv(self.READ_SIZE)
            if not data:
                return None
            self._log(f"  RX [{len(data)}B]: {data.hex()}")
            return data
        except socket.timeout:
            return None
        finally:
            self._sock.settimeout(old_timeout)

    def _wire_to_binary(self, wire_data: bytes) -> Optional[bytes]:
        if self.hex_encoding:
            try:
                hex_str = wire_data.decode('ascii').strip('\x00')
                return bytes.fromhex(hex_str)
            except (ValueError, UnicodeDecodeError):
                return None
        return wire_data

    def _recv_single_tlv(self, timeout: Optional[float] = None) -> Optional[TLV]:
        data = self._recv_raw(timeout)
        if data is None:
            return None
        raw = self._wire_to_binary(data)
        if raw is None or len(raw) < 2:
            return None
        return TLV.from_bytes(raw)

    def _send_fragment_ack(self, frag_type: int):
        ack_tlv = TLV(type=0x00, length=2, value=bytes([frag_type, 0x00]))
        data = ack_tlv.to_wire(self.hex_encoding)
        self._log(f"  FACK TX: {data.hex()}")
        self._sock.sendall(data)

    def _recv_encrypted_raw(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Leggi esattamente un frame (40 hex byte) con buffering."""
        FRAME_WIRE_SIZE = self.READ_SIZE
        if not self._sock:
            raise ConnectionError("Non connesso")

        if len(self._recv_buf) >= FRAME_WIRE_SIZE:
            frame = bytes(self._recv_buf[:FRAME_WIRE_SIZE])
            del self._recv_buf[:FRAME_WIRE_SIZE]
            self._log(f"  RX(buf) [{len(frame)}B]: {frame.hex()}")
            return frame

        effective_timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT
        deadline = time.monotonic() + effective_timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(remaining)
            try:
                data = self._sock.recv(256)
                if not data:
                    return None
                self._recv_buf.extend(data)
                if len(self._recv_buf) >= FRAME_WIRE_SIZE:
                    frame = bytes(self._recv_buf[:FRAME_WIRE_SIZE])
                    del self._recv_buf[:FRAME_WIRE_SIZE]
                    if self._recv_buf:
                        self._log(f"  RX [{len(frame)}B frame + {len(self._recv_buf)}B buffered]:"
                                  f" {frame.hex()}")
                    else:
                        self._log(f"  RX [{len(frame)}B]: {frame.hex()}")
                    return frame
                self._log(f"  RX partial [{len(data)}B], buf={len(self._recv_buf)}B, attendo...")
            except socket.timeout:
                return None
            except OSError:
                return None

    def _recv_decrypt_single(self, timeout: float = DEFAULT_TIMEOUT) -> Optional[Tuple[int, bytes]]:
        """Leggi e decripta un singolo frame cifrato."""
        data = self._recv_encrypted_raw(timeout)
        if data is None:
            return None

        raw = self._wire_to_binary(data)
        if raw is None or len(raw) < 2:
            return None

        enc_type = raw[0]
        orig_type = enc_type & 0x7F
        orig_length = raw[1]

        ct_and_tag_len = orig_length + 6
        min_len = 2 + ct_and_tag_len

        if len(raw) < min_len:
            self._log(f"  RX(enc) troppo corto: {len(raw)}B, attesi almeno {min_len}B")
            return None

        ct_and_tag = raw[2:2 + ct_and_tag_len]
        remaining = raw[2 + ct_and_tag_len:]
        counter_bytes = (remaining + b'\x00\x00\x00\x00')[:4]
        device_counter = le_to_int(counter_bytes)

        ct = ct_and_tag[:orig_length] if orig_length > 0 else b''
        tag = ct_and_tag[orig_length:orig_length + 6]

        self._log(f"  RX(enc) type=0x{orig_type:02X} len={orig_length} "
                  f"dev_counter={device_counter} tag={tag.hex()}")

        self._crypto.counter += 1
        if device_counter >= self._crypto.counter:
            self._crypto.counter = device_counter

        plaintext = self._crypto.decrypt(
            orig_type, ct, tag, device_counter,
            self._user_hash, self._user_counter, self._device_uid
        )

        if plaintext is None:
            self._log(f"  RX(enc) decrypt FAILED (type=0x{orig_type:02X} counter={device_counter})")
            return None

        self._log(f"  RX(enc) decrypted: type=0x{orig_type:02X} pt={plaintext.hex() if plaintext else 'empty'}")
        return (orig_type, plaintext)

    def _recv_encrypted_response(self, timeout: float = DEFAULT_TIMEOUT) -> Optional[AckResponse]:
        """Ricevi e decripta una risposta crittografata, con gestione frammenti e push events."""
        deadline = time.monotonic() + timeout
        max_push_skip = 5

        for _ in range(max_push_skip):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            result = self._recv_decrypt_single(remaining)
            if result is None:
                return None

            orig_type, plaintext = result

            # Push event (es. ClimaStateEvent 0x61) — skip e riprova
            if orig_type not in (0x00, 0x7F):
                self._log(f"  Push event 0x{orig_type:02X} ({len(plaintext)}B) — skip, attendo ACK")
                if orig_type == 0x61 and len(plaintext) >= 8:
                    self._parse_clima_state_event(plaintext)
                continue

            # ACK non frammentato
            if orig_type == 0x00:
                if len(plaintext) == 0:
                    return AckResponse(ack_type=0x00, ack_response=0x00, ack_data=None)
                if len(plaintext) >= 2:
                    return AckResponse(
                        ack_type=plaintext[0],
                        ack_response=plaintext[1],
                        ack_data=plaintext[2:] if len(plaintext) > 2 else None
                    )
                return None

            # Frammento (0x7F)
            break
        else:
            self._log("  Troppi push event consecutivi, timeout")
            return None

        if orig_type != 0x7F:
            return None

        # --- Frammento cifrato ---
        if len(plaintext) < 4:
            self._log(f"  FRAG(enc) malformato: {len(plaintext)}B")
            return None

        ack_type = plaintext[0]
        ack_resp = plaintext[1]
        total_frags = plaintext[2]
        frag_index = plaintext[3]
        frag_data = plaintext[4:] if len(plaintext) > 4 else b''

        self._log(f"  FRAG(enc) [{frag_index}/{total_frags}]: ack=0x{ack_type:02X} "
                  f"resp=0x{ack_resp:02X} data={len(frag_data)}B")

        fragments = [frag_data]

        for expected_idx in range(1, total_frags):
            ack_tlv = TLV(type=0x00, length=2, value=bytes([0x7F, 0x00]))
            self._send_tlv(ack_tlv)

            next_result = self._recv_decrypt_single(timeout)
            if next_result is None:
                self._log(f"  FRAG(enc) timeout aspettando frammento {expected_idx}")
                break

            next_type, next_pt = next_result
            if next_type != 0x7F or len(next_pt) < 4:
                self._log(f"  FRAG(enc) tipo inatteso: 0x{next_type:02X}")
                break

            next_frag_idx = next_pt[3]
            next_data = next_pt[4:] if len(next_pt) > 4 else b''
            self._log(f"  FRAG(enc) [{next_frag_idx}/{total_frags}]: data={len(next_data)}B")
            fragments.append(next_data)

        reassembled = b''.join(fragments)
        self._log(f"  FRAG(enc) riassemblato: {len(reassembled)}B")
        return AckResponse(ack_type=ack_type, ack_response=ack_resp,
                          ack_data=reassembled if reassembled else None)

    def _recv_response(self, timeout: float = DEFAULT_TIMEOUT) -> Optional[AckResponse]:
        """Ricevi una risposta completa con gestione frammentazione (plaintext)."""
        deadline = time.monotonic() + timeout
        max_skip = 5

        for _ in range(max_skip):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            tlv = self._recv_single_tlv(remaining)
            if tlv is None:
                return None

            if tlv.type == 0x00:
                return AckResponse.from_tlv(tlv)

            is_fragment = (tlv.type & 0x7F) == 0x7F
            if is_fragment:
                break

            # Push event o dato inatteso — skip e riprova
            self._log(f"  Skip unexpected TLV type=0x{tlv.type:02X} "
                      f"({len(tlv.value) if tlv.value else 0}B)")
            continue
        else:
            return None

        # --- Gestione frammenti ---
        if tlv.value is None or len(tlv.value) < 4:
            self._log(f"  Frammento malformato: {tlv}")
            return None

        ack_type = tlv.value[0]
        ack_resp = tlv.value[1]
        total_frags = tlv.value[2]
        frag_index = tlv.value[3]
        frag_data = tlv.value[4:] if len(tlv.value) > 4 else b''

        self._log(f"  FRAG [{frag_index}/{total_frags}]: ack=0x{ack_type:02X} "
                  f"resp=0x{ack_resp:02X} data={len(frag_data)}B")

        fragments = [frag_data]

        for expected_idx in range(1, total_frags):
            self._send_fragment_ack(tlv.type)

            next_tlv = self._recv_single_tlv(timeout)
            if next_tlv is None:
                self._log(f"  FRAG timeout aspettando frammento {expected_idx}")
                break

            if next_tlv.value and len(next_tlv.value) >= 4:
                next_frag_idx = next_tlv.value[3]
                next_data = next_tlv.value[4:] if len(next_tlv.value) > 4 else b''
                self._log(f"  FRAG [{next_frag_idx}/{total_frags}]: data={len(next_data)}B")
                fragments.append(next_data)

                next_resp = next_tlv.value[1]
                if next_resp != 0x00 and next_resp != ack_resp:
                    self._log(f"  FRAG errore: resp=0x{next_resp:02X}")
                    break
            else:
                self._log(f"  FRAG malformato: {next_tlv}")
                break

        assembled_data = b''.join(fragments)
        self._log(f"  FRAG assemblato: {len(assembled_data)}B da {len(fragments)} frammenti")

        return AckResponse(
            ack_type=ack_type,
            ack_response=ack_resp,
            ack_data=assembled_data if assembled_data else None
        )

    def _send_fragmented_command(self, opcode: int, value: bytes,
                                 timeout: float = DEFAULT_TIMEOUT) -> Optional[AckResponse]:
        """Invia un comando frammentato (value > FRAME_SIZE)."""
        data_per_frag = self.FRAME_SIZE - 2
        total_frags = math.ceil(len(value) / data_per_frag)
        if total_frags == 0:
            total_frags = 1

        self._log(f"  FRAG TX: {len(value)}B -> {total_frags} frammenti (da {data_per_frag}B)")

        for frag_idx in range(total_frags):
            offset = frag_idx * data_per_frag
            chunk = value[offset:offset + data_per_frag]

            frag_value = bytes([total_frags, frag_idx]) + chunk
            frag_tlv = TLV(type=opcode, length=len(frag_value), value=frag_value)

            self._log(f"  FRAG TX [{frag_idx+1}/{total_frags}]: {len(chunk)}B data")
            self._send_tlv(frag_tlv)

            ack = self._recv_response(timeout)
            self._log(f"  FRAG ACK [{frag_idx+1}/{total_frags}]: {ack}")

            if frag_idx < total_frags - 1:
                if not ack or not ack.success:
                    self._log(f"  FRAG errore: ACK intermedio fallito")
                    return ack
            else:
                return ack

        return None

    def on_clima_event(self, callback):
        """Registra un callback per ClimaStateEvent (0x61).

        Il callback riceve un dict con: power, scheduler, set_temp,
        room_temp, mode, fan, flap. Utile per integrazione Home Assistant.
        """
        self._event_callbacks.append(callback)

    def _parse_clima_state_event(self, data: bytes):
        """Parsa un ClimaStateEvent (0x61) push e lo salva come cache."""
        if len(data) < 8:
            return
        # Byte 0: bit0=power (i()), bit7=scheduler (h()) — confermato da DetailActivity UI
        power = bool(data[0] & 0x01)
        scheduler = bool(data[0] & 0x80)
        # Bytes 1-2=set_temp (c()), 3-4=room_temp (g()) — confermato da GET_ROOM_TEMP match
        set_temp = be_to_short(data[1:3]) / 10.0
        room_temp = be_to_short(data[3:5]) / 10.0
        mode = data[5]
        fan = data[6]
        flap = data[7]
        event = {
            'power': power, 'scheduler': scheduler,
            'set_temp': set_temp, 'room_temp': room_temp,
            'mode': mode, 'fan': fan, 'flap': flap,
        }
        self._last_clima_event = event
        self._log(f"  ClimaStateEvent: power={power} set={set_temp}C "
                  f"room={room_temp}C mode={mode} fan={fan} flap={flap}")
        for cb in self._event_callbacks:
            try:
                cb(event)
            except Exception as e:
                self._log(f"  Event callback error: {e}")

    def _send_command(self, opcode: int, value: Optional[bytes] = None,
                      timeout: float = DEFAULT_TIMEOUT,
                      _retry_on_cc: int = 1) -> Optional[AckResponse]:
        """Invia comando con lock serializzato e auto-retry su WrongCC (0xCC)."""
        with self._cmd_lock:
            return self._send_command_locked(opcode, value, timeout, _retry_on_cc)

    def _send_command_locked(self, opcode: int, value: Optional[bytes],
                              timeout: float, retries: int) -> Optional[AckResponse]:
        length = len(value) if value else 0
        self._log(f"  CMD: {Opcode.name(opcode)} value={value.hex() if value else 'None'}")

        if not self._encrypted and value and len(value) > self.FRAME_SIZE:
            return self._send_fragmented_command(opcode, value, timeout)

        tlv = TLV(type=opcode, length=length, value=value)
        self._send_tlv(tlv)

        if self._encrypted:
            ack = self._recv_encrypted_response(timeout)
        else:
            ack = self._recv_response(timeout)
        self._log(f"  RSP: {ack}")

        # Auto-retry su WrongCC (0xCC) — counter desincronizzato
        if ack and ack.ack_response == 0xCC and retries > 0:
            self._log(f"  WrongCC — retry ({retries} rimasti)")
            return self._send_command_locked(opcode, value, timeout, retries - 1)

        return ack

    # --- Probe ---

    def probe(self) -> dict:
        results = {}
        print(f"[probe] Connessione a {self.host}:{self.port}...")
        print(f"[probe] Encoding: {'hex-ASCII' if self.hex_encoding else 'binario'}")

        print("[probe] Invio GET_CERTIFICATE (0x35)...")
        ack = self._send_command(Opcode.GET_CERTIFICATE, timeout=60.0)

        if ack is None:
            print("[probe] Nessuna risposta")
            results['status'] = 'no_response'
            return results

        if ack.success:
            print(f"[probe] OK! Certificato ricevuto: {len(ack.ack_data) if ack.ack_data else 0} byte")
            if ack.ack_data:
                print(f"[probe] Primi 32B: {ack.ack_data[:32].hex()}")
                if ack.ack_data[:2] == b'\x30\x82':
                    cert_len = int.from_bytes(ack.ack_data[2:4], 'big') + 4
                    print(f"[probe] Certificato DER: {cert_len}B attesi, {len(ack.ack_data)}B ricevuti")
            results['status'] = 'ok'
            results['cert_len'] = len(ack.ack_data) if ack.ack_data else 0
        else:
            print(f"[probe] Risposta errore: {ack}")
            results['status'] = 'error'

        return results

    # --- Pairing ---

    def pair(self, pin: int, user_id: str = "olimpia-python",
             device_uid_override: Optional[str] = None) -> bool:
        """Pairing ECDH completo (10 step + PIN opzionale)."""
        self._crypto = OlimpiaCrypto()
        self._user_hash = hash_user_id(user_id)
        self._user_counter = 0

        print(f"[pair] userId: {user_id}")
        print(f"[pair] hash: {self._user_hash.hex()}")

        # 1. GET_CERTIFICATE
        print("[pair] 1/8 GET_CERTIFICATE...")
        ack = self._send_command(Opcode.GET_CERTIFICATE, timeout=60.0)
        if not ack or not ack.success:
            print(f"[pair] FAIL: {ack}")
            return False
        cert_data = ack.ack_data
        print(f"[pair] Certificato: {len(cert_data)}B")

        from cryptography import x509
        cert = x509.load_der_x509_certificate(cert_data)
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
        print(f"[pair] Certificate CN: {cn}")
        if device_uid_override:
            uid_str = device_uid_override
        else:
            uid_str = f"{int(cn):08d}"
        self._device_uid = uid_str.encode('utf-8')
        print(f"[pair] Device UID (AAD): {uid_str}")

        # 2. INIT_DH
        print("[pair] 2/8 INIT_DH (invio pubkey)...")
        self._crypto.generate_keypair()
        pubkey = self._crypto.get_pubkey_bytes()
        ack = self._send_command(Opcode.INIT_DH, pubkey, timeout=15.0)
        if not ack or not ack.success:
            print(f"[pair] FAIL: {ack}")
            return False

        # 3. GET_DH_PUBKEY
        print("[pair] 3/8 GET_DH_PUBKEY...")
        ack = self._send_command(Opcode.GET_DH_PUBKEY, timeout=10.0)
        if not ack or not ack.success or not ack.ack_data:
            print(f"[pair] FAIL: {ack}")
            return False
        self._crypto.set_device_pubkey(ack.ack_data)
        self._crypto.compute_shared_secret()
        self._crypto.compute_ltk()
        print(f"[pair] Shared secret + LTK calcolati")

        # 4. GET_SIGNATURE
        print("[pair] 4/8 GET_SIGNATURE...")
        ack = self._send_command(Opcode.GET_SIGNATURE, timeout=15.0)
        if not ack or not ack.success or not ack.ack_data:
            print(f"[pair] FAIL: {ack}")
            return False
        print(f"[pair] Firma: {len(ack.ack_data)}B (verifica skippata)")

        # 5. SEND_HASH_USERID
        print("[pair] 5/8 SEND_HASH_USERID...")
        ack = self._send_command(Opcode.SEND_HASH_USERID, self._user_hash)
        if not ack or not ack.success:
            print(f"[pair] FAIL: {ack}")
            return False

        # 6. SEND_USER_COUNTER
        print("[pair] 6/8 SEND_USER_COUNTER...")
        ack = self._send_command(Opcode.SEND_USER_COUNTER,
                                bytes([self._user_counter]))
        if not ack or not ack.success:
            print(f"[pair] FAIL: {ack}")
            return False
        if ack.ack_data:
            dev_counter = le_to_int(ack.ack_data)
            self._user_counter = dev_counter
            print(f"[pair] Device counter: {dev_counter} (usato per AAD)")

        # 7. SEND_SESSION_RANDOM
        print("[pair] 7/8 SEND_SESSION_RANDOM...")
        rnd_host = os.urandom(8)
        ack = self._send_command(Opcode.SEND_SESSION_RANDOM, rnd_host)
        if not ack or not ack.success or not ack.ack_data:
            print(f"[pair] FAIL: {ack}")
            return False
        rnd_device = ack.ack_data
        self._crypto.compute_session_key(rnd_host, rnd_device)
        print(f"[pair] Session key calcolata")

        # 8. SEND_IV_HEAD
        print("[pair] 8/8 SEND_IV_HEAD...")
        iv_head = self._crypto.generate_iv_head()
        ack = self._send_command(Opcode.SEND_IV_HEAD, iv_head)
        if not ack or not ack.success:
            print(f"[pair] FAIL: {ack}")
            return False

        self._encrypted = True
        print("[pair] Crittografia AES-GCM attiva!")

        save_credentials(self.host, user_id, self._user_hash,
                        self._user_counter, self._crypto, self._device_uid)

        # 9/10. Ri-invio crittografato per conferma identita'
        print("[pair] 9/10 SEND_HASH_USERID (encrypted)...")
        ack = self._send_command(Opcode.SEND_HASH_USERID, self._user_hash)
        if not ack or not ack.success:
            print(f"[pair] WARN: {ack}")

        print("[pair] 10/10 SEND_USER_COUNTER (encrypted)...")
        ack = self._send_command(Opcode.SEND_USER_COUNTER,
                                bytes([self._user_counter]))
        if not ack:
            print(f"[pair] WARN: {ack}")
        elif ack.success and ack.ack_data:
            final_counter = le_to_int(ack.ack_data)
            print(f"[pair] Counter finale: {final_counter}")

        # 11. SEND_PIN — persiste l'utente nel device
        if pin:
            sig = self.send_pin_encrypted(pin)
            if not sig:
                print("[pair] WARN: SEND_PIN fallito — l'utente potrebbe non essere persistito")

        # Warm-up: sincronizza counter e cattura ClimaStateEvent
        for i in range(3):
            ok = self.ping()
            if ok:
                self._crypto_ok = True
                self._log(f"[pair] Warm-up ping OK (tentativo {i+1})")
                break
            self._log(f"[pair] Warm-up ping fallito (tentativo {i+1})")
        if self._last_clima_event:
            print(f"[pair] ClimaStateEvent: power={'ON' if self._last_clima_event['power'] else 'OFF'} "
                  f"room={self._last_clima_event['room_temp']}C")

        print("[pair] PAIRING COMPLETATO!")
        return True

    def send_pin_encrypted(self, pin: int) -> Optional[bytes]:
        """Invia SEND_PIN (0x46) cifrato dopo il pairing."""
        if not self._encrypted:
            print("[pin] ERRORE: crittografia non attiva!")
            return None

        pin_bytes = int_to_bigint_bytes(pin)
        print(f"[pin] SEND_PIN (encrypted) pin={pin} bytes={pin_bytes.hex()}")
        ack = self._send_command(Opcode.SEND_PIN, pin_bytes, timeout=35.0)
        if not ack:
            print("[pin] Timeout (35s)")
            return None
        if not ack.success:
            print(f"[pin] Errore: {ack}")
            return None

        sig = ack.ack_data
        print(f"[pin] PIN accettato! Firma: {len(sig) if sig else 0}B")
        return sig

    # --- Authenticate (reconnect) ---

    def _drain_pending_data(self, timeout: float = 0.5):
        """Consuma e scarta dati pendenti dal device (push events, dati cifrati residui)."""
        if not self._sock:
            return
        old_timeout = self._sock.gettimeout()
        self._sock.settimeout(timeout)
        try:
            while True:
                data = self._sock.recv(self.READ_SIZE)
                if not data:
                    break
                self._log(f"  DRAIN: {len(data)}B scartati: {data.hex()}")
        except socket.timeout:
            pass
        finally:
            self._sock.settimeout(old_timeout)

    def authenticate(self, user_id: str = "olimpia-python") -> bool:
        """Autenticazione con credenziali salvate (flow reconnect)."""
        self._recv_buf.clear()
        self._drain_pending_data()
        creds = load_credentials(self.host)
        if not creds:
            print("[auth] Nessuna credenziale salvata. Esegui prima 'pair'.")
            return False

        self._user_hash = bytes.fromhex(creds['user_hash'])
        self._user_counter = creds['user_counter']
        if creds.get('device_uid'):
            self._device_uid = bytes.fromhex(creds['device_uid'])
        crypto_data = creds['crypto']

        self._crypto = OlimpiaCrypto()
        if crypto_data['shared_secret']:
            self._crypto.shared_secret = bytes.fromhex(crypto_data['shared_secret'])

        ltk_saved = bytes.fromhex(crypto_data['ltk']) if crypto_data['ltk'] else None
        ltk_derived = None
        if self._crypto.shared_secret:
            ltk_derived = hashlib.sha256(self._crypto.shared_secret).digest()[:16]

        if ltk_saved:
            self._crypto.ltk = ltk_saved
            if ltk_derived and ltk_saved != ltk_derived:
                print(f"[auth] WARN: LTK salvata != LTK derivata!")
            elif ltk_derived:
                print(f"[auth] LTK OK (saved == derived)")
        elif ltk_derived:
            self._crypto.ltk = ltk_derived
            print(f"[auth] LTK derivata da shared_secret")
        else:
            print("[auth] ERRORE: nessuna LTK disponibile!")
            return False

        print(f"[auth] Credenziali caricate per {self.host}")
        print(f"[auth]   user_hash:    {self._user_hash.hex()}")
        print(f"[auth]   device_uid:   {self._device_uid.hex() if self._device_uid else 'None'}")
        print(f"[auth]   ltk:          {self._crypto.ltk.hex()}")
        print(f"[auth]   user_counter: {self._user_counter}")

        # Flow reconnect: M -> Q -> P -> N

        print("[auth] 1/4 SEND_HASH_USERID...")
        ack = self._send_command(Opcode.SEND_HASH_USERID, self._user_hash)
        if not ack or not ack.success:
            print(f"[auth] FAIL: {ack}")
            return False

        print(f"[auth] 2/4 SEND_USER_COUNTER (sending {self._user_counter})...")
        ack = self._send_command(Opcode.SEND_USER_COUNTER,
                                bytes([self._user_counter]))
        if not ack or not ack.success:
            print(f"[auth] FAIL: {ack}")
            return False
        if ack.ack_data:
            dev_counter = le_to_int(ack.ack_data)
            print(f"[auth]   Device counter: {dev_counter} (sent: {self._user_counter})")
            if dev_counter != self._user_counter:
                print(f"[auth]   WARN counter mismatch — aggiorno a {dev_counter}")
                self._user_counter = dev_counter

        print("[auth] 3/4 SEND_SESSION_RANDOM...")
        rnd_host = os.urandom(8)
        ack = self._send_command(Opcode.SEND_SESSION_RANDOM, rnd_host)
        if not ack or not ack.success or not ack.ack_data:
            print(f"[auth] FAIL: {ack}")
            return False
        rnd_device = ack.ack_data
        self._crypto.compute_session_key(rnd_host, rnd_device)
        print(f"[auth]   session_key:  {self._crypto.session_key.hex()}")

        print("[auth] 4/4 SEND_IV_HEAD...")
        iv_head = self._crypto.generate_iv_head()
        ack = self._send_command(Opcode.SEND_IV_HEAD, iv_head)
        if not ack or not ack.success:
            print(f"[auth] FAIL: {ack}")
            return False
        if ack.ack_data and len(ack.ack_data) == 8:
            print(f"[auth]   Device iv_head diverso dal nostro! Uso device iv_head per decrypt.")
            self._crypto.device_iv_head = ack.ack_data

        self._encrypted = True
        self._crypto.counter = 0

        print(f"[auth] Crittografia attiva!")

        # Warm-up: sincronizza counter e cattura ClimaStateEvent
        for i in range(3):
            ok = self.ping()
            if ok:
                self._crypto_ok = True
                self._log(f"[auth] Warm-up ping OK (tentativo {i+1})")
                break
            self._log(f"[auth] Warm-up ping fallito (tentativo {i+1})")
        if not self._crypto_ok:
            print("[auth] Decrypt risposte fallito — credenziali potrebbero essere obsolete.")
        if self._last_clima_event:
            print(f"[auth] ClimaStateEvent ricevuto: power={'ON' if self._last_clima_event['power'] else 'OFF'} "
                  f"room={self._last_clima_event['room_temp']}C")

        save_credentials(self.host, user_id, self._user_hash,
                        self._user_counter, self._crypto, self._device_uid)

        return True

    def authenticate_from_dict(self, creds: dict, user_id: str = "olimpia-python") -> bool:
        """Autenticazione da dict (per HA, senza filesystem)."""
        self._encrypted = False
        self._crypto_ok = False
        self._recv_buf.clear()
        self._drain_pending_data()

        self._user_hash = bytes.fromhex(creds['user_hash'])
        self._user_counter = creds['user_counter']
        if creds.get('device_uid'):
            self._device_uid = bytes.fromhex(creds['device_uid'])
        crypto_data = creds['crypto']

        self._crypto = OlimpiaCrypto()
        if crypto_data['shared_secret']:
            self._crypto.shared_secret = bytes.fromhex(crypto_data['shared_secret'])

        ltk_saved = bytes.fromhex(crypto_data['ltk']) if crypto_data['ltk'] else None
        ltk_derived = None
        if self._crypto.shared_secret:
            ltk_derived = hashlib.sha256(self._crypto.shared_secret).digest()[:16]

        if ltk_saved:
            self._crypto.ltk = ltk_saved
        elif ltk_derived:
            self._crypto.ltk = ltk_derived
        else:
            self._log("[auth] ERRORE: nessuna LTK disponibile!")
            return False

        self._log(f"[auth] Credenziali caricate per {self.host}")

        # Flow reconnect: M -> Q -> P -> N
        ack = self._send_command(Opcode.SEND_HASH_USERID, self._user_hash)
        if not ack or not ack.success:
            self._log_warn(f"[auth] SEND_HASH_USERID FAIL: {ack}")
            return False

        ack = self._send_command(Opcode.SEND_USER_COUNTER,
                                bytes([self._user_counter]))
        if not ack or not ack.success:
            self._log_warn(f"[auth] SEND_USER_COUNTER FAIL: {ack}")
            return False
        if ack.ack_data:
            dev_counter = le_to_int(ack.ack_data)
            if dev_counter != self._user_counter:
                self._user_counter = dev_counter

        rnd_host = os.urandom(8)
        ack = self._send_command(Opcode.SEND_SESSION_RANDOM, rnd_host)
        if not ack or not ack.success or not ack.ack_data:
            self._log_warn(f"[auth] SEND_SESSION_RANDOM FAIL: {ack}")
            return False
        rnd_device = ack.ack_data
        self._crypto.compute_session_key(rnd_host, rnd_device)

        iv_head = self._crypto.generate_iv_head()
        ack = self._send_command(Opcode.SEND_IV_HEAD, iv_head)
        if not ack or not ack.success:
            self._log_warn(f"[auth] SEND_IV_HEAD FAIL: {ack}")
            return False
        if ack.ack_data and len(ack.ack_data) == 8:
            self._crypto.device_iv_head = ack.ack_data

        self._encrypted = True
        self._crypto.counter = 0

        # Warm-up ping
        for i in range(3):
            if self.ping():
                self._crypto_ok = True
                break

        return True

    # --- Comandi HVAC ---

    def _set_command(self, opcode: int, value: Optional[bytes] = None,
                     timeout: float = DEFAULT_TIMEOUT) -> bool:
        """Invia comando SET e poi COMMIT per applicare."""
        ack = self._send_command(opcode, value, timeout)
        if not ack or not ack.success:
            return False
        # COMMIT per applicare la modifica
        commit_ack = self._send_command(Opcode.COMMIT)
        if commit_ack:
            self._log(f"  COMMIT: success={commit_ack.success}")
        return True

    def ping(self) -> bool:
        ack = self._send_command(Opcode.PING)
        return ack is not None and ack.success

    def power_on(self) -> bool:
        ack = self._send_command(Opcode.POWER_ON)
        return ack is not None and ack.success

    def power_off(self) -> bool:
        return self._set_command(Opcode.POWER_OFF)

    def set_temperature(self, temp_celsius: float) -> bool:
        value_int = int(math.ceil(temp_celsius)) * 10
        value = int_to_le(value_int, 2)
        return self._set_command(Opcode.SET_TEMPERATURE, value)

    def get_room_temperature(self) -> Optional[float]:
        ack = self._send_command(Opcode.GET_ROOM_TEMP, timeout=40.0)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return be_to_short(ack.ack_data) / 10.0

    def set_mode(self, mode: Mode) -> bool:
        return self._set_command(Opcode.SET_MODE, bytes([int(mode)]))

    def get_mode(self) -> Optional[int]:
        ack = self._send_command(Opcode.GET_MODE)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return le_to_int(ack.ack_data)

    def set_fan(self, fan: Fan) -> bool:
        return self._set_command(Opcode.SET_FAN, bytes([int(fan)]))

    def get_fan(self) -> Optional[int]:
        ack = self._send_command(Opcode.GET_FAN)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return le_to_int(ack.ack_data)

    def toggle_scheduler(self, enabled: bool) -> bool:
        ack = self._send_command(Opcode.TOGGLE_SCHEDULER,
                                 bytes([1 if enabled else 0]))
        return ack is not None and ack.success

    def toggle_flap(self, swing: bool) -> bool:
        """Imposta flap SWING/FIXED. Opcode 0x16 è un toggle, quindi
        legge lo stato corrente e invia solo se diverso dal desiderato."""
        current = self._last_clima_event.get('flap') if self._last_clima_event else None
        if current is None:
            self.get_status_safe()
            current = self._last_clima_event.get('flap') if self._last_clima_event else None

        current_swing = (current == 1) if current is not None else None
        if current_swing == swing:
            return True  # Gia' nello stato desiderato

        ack = self._send_command(Opcode.TOGGLE_FLAP)
        if not ack or not ack.success:
            return False
        # NO COMMIT — il commit annulla il toggle.
        # Ping post-toggle per finalizzare (come fa l'app Java con 0x28 dopo power on/off).
        self.ping()
        self._poll_for_events(1.5)
        return True

    def set_buzzer(self, enabled: bool) -> bool:
        ack = self._send_command(Opcode.SET_BUZZER,
                                 bytes([1 if enabled else 0]))
        return ack is not None and ack.success

    def commit(self) -> bool:
        ack = self._send_command(Opcode.COMMIT)
        return ack is not None and ack.success

    def check_query(self) -> bool:
        ack = self._send_command(Opcode.CHECK_QUERY, timeout=3.0)
        return ack is not None and ack.success

    def get_min_settable_temp(self, mode: Optional[int] = None) -> Optional[float]:
        """Legge la temperatura MINIMA impostabile per il modo dato (opcode 0x19).

        NOTA: NON ritorna il setpoint corrente. Il setpoint reale e' disponibile
        solo via push event ClimaStateEvent (0x61, bytes 3-4).
        """
        if mode is None:
            mode = self.get_mode()
            if mode is None:
                return None
        ack = self._send_command(Opcode.GET_SET_TEMP_MIN, bytes([mode]))
        if not ack or not ack.success or not ack.ack_data:
            return None
        return be_to_short(ack.ack_data) / 10.0

    def refresh(self) -> bool:
        """Invia REFRESH (0x31) per richiedere stato aggiornato.
        Il device risponde con ClimaStateEvent (0x61) push."""
        ack = self._send_command(Opcode.COMMIT)
        return ack is not None and ack.success

    def _poll_for_events(self, timeout: float = 1.0):
        """Legge push events pendenti dal socket (es. ClimaStateEvent 0x61).
        Non invia comandi — solo ricezione passiva."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            result = self._recv_decrypt_single(remaining)
            if result is None:
                return
            orig_type, plaintext = result
            if orig_type == 0x61 and len(plaintext) >= 8:
                self._parse_clima_state_event(plaintext)
                return  # 0x61 ricevuto, possiamo fermarci

    def get_status_safe(self) -> dict:
        """Legge stato completo da ClimaStateEvent (0x61) push.

        NON invia mai comandi pericolosi (0x16 = toggle, 0x19 = possibile scrittura).
        Power e setpoint sono disponibili SOLO via ClimaStateEvent.
        Il 0x61 arriva ~1.5-2s dopo il primo comando post-auth — i GET individuali
        servono sia a raccogliere dati sia a dare tempo al push di arrivare.
        """
        def _from_event(ce):
            return {
                'power': ce.get('power'), 'mode': ce.get('mode'),
                'fan': ce.get('fan'), 'set_temp': ce.get('set_temp'),
                'room_temp': ce.get('room_temp'),
                'buzzer': None, 'from_cache': True,
            }

        # 1. Cache gia' disponibile
        ce = self._last_clima_event
        if ce:
            self._log("[status] Uso ClimaStateEvent cache")
            return _from_event(ce)

        if not self._crypto_ok:
            self._log("[status] Crypto non OK, skip query")
            return {
                'power': None, 'mode': None, 'fan': None,
                'set_temp': None, 'room_temp': None, 'buzzer': None,
                'from_cache': False,
            }

        # 2. Invio GET sicuri — ogni risposta puo' portare il 0x61 come side-effect
        self._log("[status] GET sicuri per stimolare ClimaStateEvent")
        room_temp = self.get_room_temperature()  # 0x17
        ce = self._last_clima_event
        if ce:
            self._log("[status] ClimaStateEvent ricevuto dopo GET_ROOM_TEMP")
            return _from_event(ce)

        mode = self.get_mode()  # 0x13
        ce = self._last_clima_event
        if ce:
            self._log("[status] ClimaStateEvent ricevuto dopo GET_MODE")
            return _from_event(ce)

        fan = self.get_fan()  # 0x15
        ce = self._last_clima_event
        if ce:
            self._log("[status] ClimaStateEvent ricevuto dopo GET_FAN")
            return _from_event(ce)

        # 3. 0x61 non arrivato durante i GET — poll esplicito fino a 1.5s
        #    Il push arriva ~1.5-2s dopo il primo comando post-auth
        self._log("[status] Poll esplicito per ClimaStateEvent (1.5s)")
        self._poll_for_events(timeout=1.5)
        ce = self._last_clima_event
        if ce:
            self._log("[status] ClimaStateEvent ricevuto durante poll")
            return _from_event(ce)

        # 4. Fallback: dati GET individuali, power/set_temp/buzzer non disponibili
        self._log("[status] ClimaStateEvent non ricevuto, fallback GET individuali")
        return {
            'power': None,
            'mode': mode, 'fan': fan,
            'set_temp': None,
            'room_temp': room_temp,
            'buzzer': None, 'from_cache': False,
        }

    # --- Comandi informativi ---

    def get_model(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_MODEL)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_serial(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_SERIAL)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_name(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_NAME)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_ip(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_IP)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_mac(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_MAC, timeout=30.0)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_fw_version(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_FW_VERSION)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_hw_version(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_HW_VERSION)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_server_version(self) -> Optional[str]:
        ack = self._send_command(Opcode.GET_SERVER_VERSION)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return ack.ack_data.decode('ascii', errors='replace').strip()

    def get_buzzer(self) -> Optional[bool]:
        ack = self._send_command(Opcode.GET_BUZZER)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return le_to_int(ack.ack_data) != 0

    def get_min_temp(self) -> Optional[float]:
        ack = self._send_command(Opcode.GET_MIN_TEMP)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return be_to_short(ack.ack_data) / 10.0

    def get_conn_counter(self) -> Optional[int]:
        ack = self._send_command(Opcode.GET_CONN_COUNTER)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return le_to_int(ack.ack_data)

    def get_err_status(self) -> Optional[int]:
        ack = self._send_command(Opcode.GET_ERR_STATUS)
        if not ack or not ack.success or not ack.ack_data:
            return None
        return le_to_int(ack.ack_data)

    def send_raw(self, opcode: int, value: Optional[bytes] = None,
                 timeout: float = DEFAULT_TIMEOUT) -> Optional[AckResponse]:
        return self._send_command(opcode, value, timeout)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
