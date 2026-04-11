"""Enumerazioni e codici opcode del protocollo Olimpia."""

from enum import IntEnum


class Mode(IntEnum):
    HEATING = 0
    COOLING = 1
    DEHUMY = 2
    FAN = 3
    AUTO = 4


class Fan(IntEnum):
    LOW = 0
    MEDIUM = 1
    MAX = 2
    AUTO = 3


class Flap(IntEnum):
    FIXED = 0
    SWING = 1


class AckStatus(IntEnum):
    SUCCESS = 0x00
    WRONG_CC = 0xCC


class Opcode:
    GET_SERVER_VERSION = 0x01
    SET_SSID = 0x03
    GET_MODEL = 0x04
    SET_PASSWORD = 0x05
    GET_HW_VERSION = 0x06
    SET_NAME = 0x07
    GET_MAC = 0x08
    CHECK_QUERY = 0x09
    SET_TEMPERATURE = 0x10
    GET_MIN_TEMP = 0x11
    SET_MODE = 0x12
    GET_MODE = 0x13
    SET_FAN = 0x14
    GET_FAN = 0x15
    TOGGLE_FLAP = 0x16  # Toggle FLAP (FIXED↔SWING). Nessun payload. NO COMMIT (lo annulla).
    GET_ROOM_TEMP = 0x17
    GET_IP = 0x18
    GET_SET_TEMP_MIN = 0x19
    GET_SET_TEMP_MAX = 0x20
    GET_NAME = 0x21
    GET_SSID = 0x23
    GET_SERIAL = 0x24
    GET_CONN_STATUS = 0x25
    POWER_ON = 0x26
    POWER_OFF = 0x27
    PING = 0x28
    SET_BUZZER = 0x29
    GET_CONN_COUNTER = 0x30
    COMMIT = 0x31
    GET_BUZZER = 0x32
    INIT_DH = 0x34
    GET_CERTIFICATE = 0x35
    GET_SIGNATURE = 0x36
    GET_DH_PUBKEY = 0x37
    SEND_SESSION_RANDOM = 0x38
    SEND_IV_HEAD = 0x39
    GET_SHARED_SECRET = 0x40
    GET_DATA_TO_SIGN = 0x41
    GET_LTK = 0x42
    SEND_HASH_USERID = 0x44
    SEND_USER_COUNTER = 0x45
    SEND_PIN = 0x46
    SEND_CC = 0x47
    GET_ERR_STATUS = 0x49
    GET_FW_VERSION = 0x50
    CHECK_SEC = 0x51
    SET_ECO_MODE = 0x52  # 1 byte (0=off, 1=on). NON è toggle_flap.
    GET_MISC = 0x53
    GET_FW_RANDOM = 0x54
    SET_SCHEDULER_ENTRY = 0x55
    SET_TIMER = 0x56
    GET_SESSION_RANDOM = 0x58
    SET_SCHEDULER_DATA = 0x59
    TOGGLE_SCHEDULER = 0x5B
    GET_SCHEDULER = 0x5C
    SET_TIMER_VALUE = 0x5D

    _NAMES = None

    @classmethod
    def name(cls, opcode: int) -> str:
        if cls._NAMES is None:
            cls._NAMES = {v: k for k, v in vars(cls).items()
                         if isinstance(v, int) and not k.startswith('_')}
        return cls._NAMES.get(opcode, f'0x{opcode:02X}')
