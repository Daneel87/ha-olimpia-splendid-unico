"""Crittografia ECDH + AES-GCM per il protocollo Olimpia."""

import hashlib
import os
from typing import Optional, Tuple

from olimpia.tlv import int_to_le


class OlimpiaCrypto:
    """ECDH + AES-GCM per il protocollo Olimpia."""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.device_public_key = None
        self.shared_secret = None
        self.ltk = None
        self.session_key = None
        self.iv_head = None
        self.device_iv_head = None
        self.rnd_host = None
        self.rnd_device = None
        self.counter = 0

    def generate_keypair(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def get_pubkey_bytes(self) -> bytes:
        """EC pubkey -> 64 byte (X:32 + Y:32), come C0794a.q()."""
        nums = self.public_key.public_numbers()
        return nums.x.to_bytes(32, 'big') + nums.y.to_bytes(32, 'big')

    def set_device_pubkey(self, data: bytes):
        from cryptography.hazmat.primitives.asymmetric import ec
        if len(data) != 64:
            raise ValueError(f"Attesi 64 byte, ricevuti {len(data)}")
        x = int.from_bytes(data[:32], 'big')
        y = int.from_bytes(data[32:], 'big')
        self.device_public_key = ec.EllipticCurvePublicNumbers(
            x=x, y=y, curve=ec.SECP256R1()
        ).public_key()

    def compute_shared_secret(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        self.shared_secret = self.private_key.exchange(
            ec.ECDH(), self.device_public_key
        )

    def compute_ltk(self):
        """LTK = SHA-256(shared_secret)[0:16]"""
        self.ltk = hashlib.sha256(self.shared_secret).digest()[:16]

    def compute_session_key(self, rnd_host: bytes, rnd_device: bytes):
        """session_key = AES-ECB(LTK, rndDevice[0:8] || rndHost[0:8])"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        plaintext = rnd_device[:8] + rnd_host[:8]
        cipher = Cipher(algorithms.AES(self.ltk), modes.ECB())
        enc = cipher.encryptor()
        self.session_key = enc.update(plaintext) + enc.finalize()
        self.rnd_host = rnd_host
        self.rnd_device = rnd_device

    def generate_iv_head(self) -> bytes:
        self.iv_head = os.urandom(8)
        return self.iv_head

    def _build_aad(self, type_byte: int, user_hash: bytes,
                   user_counter: int, device_uid: bytes) -> bytes:
        """AAD = [type_byte] [user_hash] [user_counter_1B] [device_uid]"""
        aad = bytearray()
        aad.append(type_byte & 0xFF)
        aad.extend(user_hash)
        aad.append(user_counter & 0xFF)
        aad.extend(device_uid)
        return bytes(aad)

    def encrypt(self, type_byte: int, plaintext: Optional[bytes],
                user_hash: bytes, user_counter: int,
                device_uid: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt AES-GCM con tag 48-bit. Returns (ciphertext, tag_6B, counter_4B)."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        self.counter += 1
        counter_bytes = int_to_le(self.counter, 4)
        nonce = self.iv_head + counter_bytes
        aad = self._build_aad(type_byte, user_hash, user_counter, device_uid)
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce))
        enc = cipher.encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(plaintext or b'') + enc.finalize()
        tag = enc.tag[:6]
        return ct, tag, counter_bytes

    def decrypt(self, type_byte: int, ct: bytes, tag_6B: bytes,
                device_counter: int,
                user_hash: bytes, user_counter: int,
                device_uid: bytes) -> Optional[bytes]:
        """Decrypt AES-GCM con tag 48-bit."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        counter_bytes = int_to_le(device_counter, 4)
        iv_heads = [self.device_iv_head] if self.device_iv_head else []
        iv_heads.append(self.iv_head)
        aad = self._build_aad(type_byte, user_hash, user_counter, device_uid)
        for iv in iv_heads:
            nonce = iv + counter_bytes
            try:
                cipher = Cipher(
                    algorithms.AES(self.session_key),
                    modes.GCM(nonce, tag_6B, min_tag_length=6)
                )
                dec = cipher.decryptor()
                dec.authenticate_additional_data(aad)
                return dec.update(ct) + dec.finalize()
            except Exception:
                continue
        return None

    def to_dict(self) -> dict:
        return {
            'shared_secret': self.shared_secret.hex() if self.shared_secret else None,
            'ltk': self.ltk.hex() if self.ltk else None,
            'session_key': self.session_key.hex() if self.session_key else None,
            'iv_head': self.iv_head.hex() if self.iv_head else None,
            'rnd_host': self.rnd_host.hex() if self.rnd_host else None,
            'rnd_device': self.rnd_device.hex() if self.rnd_device else None,
            'counter': self.counter,
        }
