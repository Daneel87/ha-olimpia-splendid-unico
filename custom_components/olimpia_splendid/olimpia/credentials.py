"""Gestione credenziali persistite su disco."""

import json
from pathlib import Path
from typing import Optional

from .crypto import OlimpiaCrypto

CREDS_DIR = Path.home() / '.olimpia'


def save_credentials(host: str, user_id: str, user_hash: bytes,
                     user_counter: int, crypto: OlimpiaCrypto,
                     device_uid: Optional[bytes] = None):
    CREDS_DIR.mkdir(exist_ok=True)
    data = {
        'host': host,
        'user_id': user_id,
        'user_hash': user_hash.hex(),
        'user_counter': user_counter,
        'device_uid': device_uid.hex() if device_uid else None,
        'crypto': crypto.to_dict(),
    }
    path = CREDS_DIR / f'{host}.json'
    path.write_text(json.dumps(data, indent=2))
    print(f"[creds] Salvate in {path}")


def load_credentials(host: str) -> Optional[dict]:
    path = CREDS_DIR / f'{host}.json'
    if not path.exists():
        return None
    return json.loads(path.read_text())
