"""TLV (Type-Length-Value) e utility di conversione byte."""

from dataclasses import dataclass
from typing import Optional

from .enums import AckStatus, Opcode


@dataclass
class TLV:
    type: int
    length: int
    value: Optional[bytes]

    def to_bytes(self) -> bytes:
        result = bytes([self.type, self.length])
        if self.value is not None:
            result += self.value
        return result

    def to_wire(self, hex_encoding: bool = True) -> bytes:
        raw = self.to_bytes()
        if hex_encoding:
            return raw.hex().encode('ascii')
        return raw

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['TLV']:
        if len(data) < 2:
            return None
        type_byte = data[0]
        length = data[1]
        if length == 0:
            return cls(type=type_byte, length=0, value=None)
        if len(data) < 2 + length:
            return None
        return cls(type=type_byte, length=length, value=data[2:2 + length])

    @classmethod
    def from_wire(cls, wire_data: bytes, hex_encoding: bool = True) -> Optional['TLV']:
        if hex_encoding:
            try:
                hex_str = wire_data.decode('ascii').strip('\x00')
                if not hex_str:
                    return None
                raw = bytes.fromhex(hex_str)
                return cls.from_bytes(raw)
            except (ValueError, UnicodeDecodeError):
                return None
        return cls.from_bytes(wire_data)

    def __repr__(self):
        val = self.value.hex() if self.value else 'None'
        return f'TLV(type=0x{self.type:02X}, len={self.length}, val={val})'


@dataclass
class AckResponse:
    ack_type: int
    ack_response: int
    ack_data: Optional[bytes]

    @property
    def success(self) -> bool:
        return self.ack_response == AckStatus.SUCCESS

    @classmethod
    def from_tlv(cls, tlv: TLV) -> Optional['AckResponse']:
        if tlv.type != 0x00:
            return None
        if tlv.value is None or len(tlv.value) < 2:
            return None
        return cls(
            ack_type=tlv.value[0],
            ack_response=tlv.value[1],
            ack_data=tlv.value[2:] if len(tlv.value) > 2 else None
        )

    def __repr__(self):
        status = 'OK' if self.success else f'ERR(0x{self.ack_response:02X})'
        data = self.ack_data.hex() if self.ack_data else 'None'
        return f'Ack(cmd={Opcode.name(self.ack_type)}, {status}, data={data})'


# --- Conversioni byte ---

def int_to_le(value: int, size: int) -> bytes:
    result = bytearray(size)
    for i in range(size):
        result[i] = (value >> (i * 8)) & 0xFF
    return bytes(result)


def le_to_int(data: bytes) -> int:
    result = 0
    for i, b in enumerate(data):
        result |= (b & 0xFF) << (i * 8)
    return result


def be_to_short(data: bytes) -> int:
    if len(data) < 2:
        return data[0] & 0xFF if data else 0
    return ((data[0] & 0xFF) << 8) | (data[1] & 0xFF)


def int_to_bigint_bytes(value: int) -> bytes:
    """Int -> BigInteger.toByteArray() (big-endian, signed, minimal length)."""
    if value == 0:
        return b'\x00'
    n_bytes = (value.bit_length() + 8) // 8
    return value.to_bytes(n_bytes, 'big', signed=True)


def hash_user_id(user_id: str) -> bytes:
    """SHA-256(user_id.encode())[0:8] — come C0794a.f()"""
    import hashlib
    return hashlib.sha256(user_id.encode()).digest()[:8]
