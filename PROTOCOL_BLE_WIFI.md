# Olimpia Splendid Unico — BLE & WiFi Protocol

Combined documentation for BLE and WiFi transports.

**Source**: Reverse-engineered from APK `it.olimpiasplendid.unico.app_1.0.9.apk` (Codermine) and verified against the physical device.

---

## 1. Transport Comparison

| Feature | WiFi (TCP) | BLE (GATT) |
|-|-|-|
| Transport | TCP socket | BLE GATT write+notify |
| Endpoint | IP:2000 | Service `669a0c20-0008-...-f99570666da3` |
| Wire encoding | Hex-ASCII (each byte → 2 hex chars) | Raw binary |
| Max frame | 20 bytes binary (40 hex chars on wire) | 20 bytes (ATT MTU 23 − 3) |
| Plaintext chunk | 16 bytes payload + 2 frag header = 18 | 16 bytes payload + 2 frag header = 18 |
| Encrypted max value | 8 bytes | 8 bytes |
| Encrypted chunk | 6 bytes payload + 2 frag header | 6 bytes payload + 2 frag header |
| Discovery | IP address + port 2000 | BLE scan, manufacturer data marker `[0x1B, 0x2C]` |
| Fragmentation ACK | Device sends ACK TLV between TX frags | Same (+ host sends ACK between RX frags) |
| RX frag ACK from host | Not required (TCP handles ordering) | Required: `[0x00, 0x02, 0x7F, 0x00]` between each RX fragment |
| Encryption | AES-128-GCM (identical parameters) | AES-128-GCM (identical parameters) |
| Usage | Steady-state control & monitoring | Initial provisioning + pairing |
| Connection timeout | 8000 ms | 15000 ms |
| Reconnect | Yes (abbreviated 4-step auth) | No (BLE used only for initial setup) |

---

## 2. BLE Transport

### 2.1 GATT Service & Characteristics

| Role | UUID |
|-|-|
| Service | `669a0c20-0008-f4bd-e611-f99570666da3` |
| Write (TX → device) | `669a0c20-0008-f4bd-e611-f99571666da3` |
| Notify (RX ← device) | `669a0c20-0008-f4bd-e611-f99572666da3` |

**MTU**: 18 bytes usable (2-byte frag header + 16-byte payload). The ATT payload is 20 bytes (MTU 23 − 3 ATT overhead); the 2-byte TLV header uses the first 2 bytes, leaving 18 for the TLV value field.

After connecting, enable notifications on the Notify characteristic. The Java app sleeps 150 ms after GATT setup before sending commands.

### 2.2 Wire Encoding

Unlike WiFi (hex-ASCII), BLE transmits **raw binary bytes**. A TLV `[0x26, 0x00]` is sent as exactly those 2 bytes, not as ASCII `"2600"`.

### 2.3 Advertising & Discovery

Olimpia devices advertise with manufacturer-specific data containing:

| Offset | Length | Content |
|-|-|-|
| 0 | 8 | Device UID (ASCII, e.g. `"00014980"`) |
| 8 | 2 | Olimpia marker: `[0x1B, 0x2C]` |

Detection: scan for BLE devices, check if any manufacturer data blob has `bytes[8:10] == [0x1B, 0x2C]`.

**Note**: The marker is not always present in advertising data. The device name (e.g. `"OL01"`) can be used as a secondary filter.

### 2.4 Write Reliability

BLE writes use `write_with_response` (ATT Write Request). On weak signal, ATT error `0x0E` ("Unlikely Error") may occur. Retry with exponential backoff (0.5s, 1.0s, 1.5s..., up to 5 attempts).

---

## 3. TLV Format

The TLV (Type-Length-Value) packet format is identical on both transports:

```
[Type: 1 byte] [Length: 1 byte] [Value: 0-N bytes]
```

Response format: `[0x00] [length] [ackType] [ackResponse] [ackData...]`
- `ackResponse = 0x00` → success
- `ackResponse = 0xCC` → WrongCC (counter check failed)

---

## 4. BLE Fragmentation

This is the main BLE-specific section. Fragmentation on BLE differs from WiFi due to the half-duplex nature of GATT: the host must explicitly ACK each received fragment, and the device ACKs each transmitted fragment.

### 4.1 TX Plaintext (Host → Device)

When the TLV value exceeds 16 bytes, the host splits it into 16-byte chunks with a 2-byte fragmentation header:

```
TLV(type=opcode, length=chunk_len+2, value=[total_frags, frag_idx, chunk...])
```

| Field | Size | Description |
|-|-|-|
| total_frags | 1 byte | Total number of fragments (1-based) |
| frag_idx | 1 byte | Current fragment index (0-based) |
| chunk | ≤16 bytes | Payload data for this fragment |

Each fragment is a complete TLV with the original opcode. Max frame = 2 (TLV header) + 2 (frag header) + 16 (chunk) = 20 bytes.

**Flow**:
1. Send fragment 0
2. Wait for device ACK notification
3. Send fragment 1
4. Wait for device ACK notification
5. ... repeat until last fragment
6. After last fragment, wait for the **command response** (not just an ACK)

**Example**: `INIT_DH` with 64-byte EC pubkey → 4 fragments of 16 bytes each.

### 4.2 RX Plaintext (Device → Host)

Fragmented responses use type `0x7F` as a fragment marker. Format:

```
[0x7F] [len] [ackType] [ackResponse] [total_frags] [frag_idx] [payload...]
```

| Offset | Field | Description |
|-|-|-|
| 0 | `0x7F` | Fragment marker |
| 1 | len | Length of remaining bytes |
| 2 | ackType | Echo of original command opcode |
| 3 | ackResponse | `0x00` = success |
| 4 | total_frags | Total number of fragments |
| 5 | frag_idx | Current fragment index (0-based) |
| 6+ | payload | Fragment data (len − 4 bytes) |

**Host ACK**: After receiving each fragment (except the last), the host must send:

```
TLV(type=0x00, length=2, value=[0x7F, 0x00])  →  bytes: [0x00, 0x02, 0x7F, 0x00]
```

**Timing**: Insert ~80 ms delay before each ACK for BLE stability (weak signal tolerance).

**Flow**:
1. Receive fragment 0 (type=0x7F)
2. Send ACK `[0x00, 0x02, 0x7F, 0x00]`
3. Receive fragment 1
4. Send ACK
5. ... repeat until all `total_frags` fragments received
6. Reassemble payload in fragment index order

**Example**: `GET_CERTIFICATE` returns ~419 bytes → 30 fragments of ~14 bytes each.

### 4.3 TX Encrypted (Host → Device)

Encrypted frames have a tighter size budget due to the GCM tag and counter:

```
[type|0x80 (1B)] [orig_len (1B)] [ciphertext (orig_len B)] [GCM_tag (6B)] [counter (4B LE)]
```

Total overhead = 1 + 1 + 6 + 4 = 12 bytes. With max ATT payload of 20 bytes:
- **Max plaintext value per frame**: 20 − 12 = **8 bytes**
- **Max chunk with frag header**: 8 − 2 = **6 bytes**

When value > 8 bytes, fragment into 6-byte chunks:

```
For each chunk:
  frag_value = [total_frags, frag_idx] + chunk (≤6 bytes)
  encrypted_frame = encrypt(opcode, frag_value)  → ≤20 bytes
  write to GATT
  wait for device ACK (except after last fragment)
```

Each fragment is encrypted independently with incrementing counters.

### 4.4 RX Encrypted (Device → Host)

The **first fragment** arrives encrypted (type byte has bit 7 set, e.g. `0xFF` for fragment type `0x7F`). After decryption, the plaintext contains:

```
[ackType (1B)] [ackResponse (1B)] [total_frags (1B)] [frag_idx (1B)] [payload...]
```

**Subsequent fragments** arrive as **plaintext** `0x7F` (same format as § 4.2).

Between each fragment, the host sends the standard plaintext ACK: `[0x00, 0x02, 0x7F, 0x00]`.

**Critical pattern**: First encrypted, rest plaintext, with plaintext ACKs between all fragments.

**Example**: `SEND_PIN` response = ECDSA signature ~70 bytes → 18 fragments. Fragment 0 is encrypted (`0xFF`), fragments 1-17 are plaintext (`0x7F`).

### 4.5 Summary: BLE vs WiFi Fragmentation

| Aspect | WiFi | BLE |
|-|-|-|
| TX frag: device ACK between frags | Yes | Yes |
| RX frag: host ACK between frags | No (TCP handles it) | Yes (`[0x00, 0x02, 0x7F, 0x00]`) |
| RX encrypted frags | All encrypted | First encrypted, rest plaintext |
| ACK delay | None needed | ~80 ms before each ACK |

---

## 5. Encryption

Encryption is identical on both transports:

- **Algorithm**: AES-128-GCM (BouncyCastle `AES/GCM/NoPadding`)
- **Key**: 16-byte session key
- **Nonce**: 12 bytes = `IVHead[8B] + counter[4B LE]`
- **AAD**: 18 bytes = `[type(1B)] [userHash(8B)] [userCounter(1B)] [deviceUID(8B)]`
- **GCM Tag**: 6 bytes (48 bit)
- **Counter**: shared TX/RX, incremented before use

Encrypted frame on wire:
```
[type|0x80 (1B)] [orig_len (1B)] [ciphertext (orig_len B)] [tag (6B)] [counter (4B LE)]
```

On WiFi, this is then hex-encoded before transmission. On BLE, it's sent as raw bytes.

---

## 6. ECDH Pairing

The ECDH pairing flow is identical on both transports — 10 TLV steps plus encrypted `SEND_PIN`:

| Step | Opcode | Direction | Description |
|-|-|-|-|
| 1 | 0x35 | → device | GET_CERTIFICATE (X.509 DER, ~419B fragmented) |
| 2 | 0x34 | → device | INIT_DH (send host EC pubkey, 64B fragmented) |
| 3 | 0x37 | ← device | GET_DH_PUBKEY (device EC pubkey, 64B fragmented) |
| 4 | 0x36 | ← device | GET_SIGNATURE (ECDSA ~70B fragmented) |
| 5 | 0x44 | → device | SEND_HASH_USERID (SHA-256(userId)[0:8]) |
| 6 | 0x45 | → device | SEND_USER_COUNTER (request 0x00 → device returns counter) |
| 7 | 0x38 | → device | SEND_SESSION_RANDOM (8B host random → 8B device random) |
| 8 | 0x39 | → device | SEND_IV_HEAD (8B random → ACK) |
| **9** | **0x44** | **→ ENC** | **SEND_HASH_USERID (encrypted)** |
| **10** | **0x45** | **→ ENC** | **SEND_USER_COUNTER (encrypted)** |
| **11** | **0x46** | **→ ENC** | **SEND_PIN (encrypted, 35s timeout) → ECDSA signature** |

After step 8, encryption is active. Step 11 (SEND_PIN) **persists the user** on the device; without it, the ECDH session is temporary and reconnect will fail.

**Key derivation**: secp256r1 ECDH → shared secret → `LTK = SHA-256(secret)[0:16]` → `session_key = AES-ECB(LTK, rndDevice[0:8] || rndHost[0:8])`.

**device_uid**: Extracted from X.509 certificate CN. CN is zero-padded (e.g. `"0000000000014980"`), trimmed via `f"{int(cn):08d}"` → `"00014980"`, used as 8 UTF-8 bytes in AAD.

---

## 7. BLE-only Commands (WiFi Provisioning)

These opcodes are used exclusively over BLE to configure the device's WiFi connection. They differ from the shared Opcode enum used for TCP.

### 7.1 Provisioning Opcodes

| Opcode | Hex | Command | Payload | Response | Notes |
|-|-|-|-|-|-|
| 3 | `0x03` | SET_NAME | UTF-8 string (1-6 chars) | ACK | Device display name |
| 5 | `0x05` | SET_SSID | UTF-8 string | ACK | WiFi network name |
| 7 | `0x07` | SET_PASSWORD | UTF-8 string | ACK | WiFi password |
| 8 | `0x08` | GET_MAC | - | String (MAC/IP) | 30s timeout, triggers WiFi connect |
| 37 | `0x25` | GET_CONN_STATUS | - | Boolean (1=connected) | Check current WiFi state |

All provisioning commands are sent **encrypted** (after ECDH pairing).

### 7.2 WiFi Provisioning Flow

Complete sequence from BLE scan to TCP-ready:

```
1. BLE scan → find device (name filter or manufacturer marker)
2. BLE connect (GATT, enable notifications, 150ms settle)
3. ECDH pairing (steps 1-10) + SEND_PIN (step 11)
   → Encryption active, user persisted on device
4. SET_NAME (0x03, encrypted) — optional, 1-6 char device name
5. GET_CONN_STATUS (0x25, encrypted) — check current WiFi state
6. SET_SSID (0x05, encrypted) — WiFi network name
7. SET_PASSWORD (0x07, encrypted) — WiFi password
8. (2s delay for device to process)
9. GET_MAC (0x08, encrypted, 30s timeout, up to 3 attempts)
   → Device connects to WiFi and returns MAC/IP string
   → If no response: 5s delay between retry attempts
10. GET_IP (0x18, encrypted) — get device IP address
11. Save TCP credentials to ~/.olimpia/<IP>.json
12. BLE disconnect
13. TCP connect to <IP>:2000 using reconnect flow
```

**GET_MAC behavior**: The device attempts WiFi association upon receiving this command. The response is a string containing the MAC address or IP. Response is encrypted and fragmented (typically 4 fragments: first encrypted, rest plaintext).

**Timing**: After SET_PASSWORD, wait ~2s before GET_MAC. GET_MAC itself has a 30s timeout (the device needs time to associate with the WiFi network).

---

## 8. HVAC Commands

HVAC control commands are identical on both transports. The same opcodes, payloads, and response formats apply whether sent over TCP or BLE (during provisioning, before WiFi is configured).

Complete opcode table:
- Power ON/OFF (0x26/0x27)
- Temperature set/get (0x10/0x17)
- Mode set/get (0x14/0x15)
- Fan set/get (0x12/0x13)
- Flap toggle (0x52), Night mode (0x16)
- Commit rules (0x31)
- Status snapshot push (0x61, 8 bytes)

---

## 9. Reconnect / Authentication

Reconnect is **WiFi TCP only**. After initial pairing (which can be done via BLE or TCP), subsequent sessions use an abbreviated 4-step flow:

| Step | Opcode | Description |
|-|-|-|
| 1 | 0x44 | SEND_HASH_USERID (saved hash) |
| 2 | 0x45 | SEND_USER_COUNTER (saved counter) |
| 3 | 0x38 | SEND_SESSION_RANDOM (new 8B random → new device random) |
| 4 | 0x39 | SEND_IV_HEAD (new 8B IV → ACK) |

After step 4, encryption is active with a new session key derived from the new randoms but the same LTK.

**BLE is not used for reconnect** — it serves only for initial provisioning and pairing. All subsequent device control goes through TCP.

---

## 10. Cloud REST API

The cloud API acts as a transparent TLV proxy. Same protocol, different transport.

---

## 11. References

| Resource | Description |
|-|-|
| [olimpia_ble.py](custom_components/olimpia_splendid/olimpia_ble.py) | BLE client: GATT transport, fragmentation, provisioning |
| [client.py](custom_components/olimpia_splendid/olimpia/client.py) | TCP client: pairing, reconnect, HVAC commands |
| [crypto.py](custom_components/olimpia_splendid/olimpia/crypto.py) | ECDH + AES-GCM implementation |
| [tlv.py](custom_components/olimpia_splendid/olimpia/tlv.py) | TLV packet structure |
| [enums.py](custom_components/olimpia_splendid/olimpia/enums.py) | Opcodes, modes, fan speeds, flap positions |
