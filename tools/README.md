# BLE Pairing Tool for Olimpia Splendid Unico

Standalone command-line tool to perform ECDH pairing and WiFi configuration for Olimpia Splendid Unico air conditioners via Bluetooth Low Energy.

Use this tool when your Home Assistant instance does not have access to a Bluetooth adapter (e.g., running in a VM, Docker without BT passthrough, or on a remote machine). After pairing, the generated credentials can be imported into Home Assistant.

## Prerequisites

- Python 3.10+
- A machine with a Bluetooth adapter (laptop, Raspberry Pi, etc.)
- The device PIN (printed on a label on the unit)

## Installation

```bash
cd tools/
pip install -r requirements.txt
```

## Usage

### 1. Scan for devices

```bash
python olimpia_ble.py scan
```

Scans for nearby BLE devices. Olimpia units appear as "OL01". Note the MAC address (e.g., `00:2A:D8:2F:FE:9F`).

Filter by name:
```bash
python olimpia_ble.py scan --name OL01
```

### 2. Full setup (recommended)

Performs ECDH pairing, PIN authentication, and WiFi configuration in one step:

```bash
python olimpia_ble.py setup 00:2A:D8:2F:FE:9F \
    --pin 12345678 \
    --ssid "YourWiFi" \
    --password "YourPassword"
```

On success, credentials are saved to `~/.olimpia/<IP>.json` where `<IP>` is the device's IP address on your network.

### 3. Pairing only (no WiFi)

Useful if WiFi is already configured (e.g., from the official app) and you only need to register a new user:

```bash
python olimpia_ble.py pair 00:2A:D8:2F:FE:9F --pin 12345678
```

### 4. WiFi reconfiguration

Performs pairing + WiFi config. Useful to change the WiFi network:

```bash
python olimpia_ble.py wifi 00:2A:D8:2F:FE:9F \
    --pin 12345678 \
    --ssid "NewNetwork" \
    --password "NewPassword"
```

All commands accept `-v` for verbose output.

## Importing credentials into Home Assistant

After a successful `setup` command, you have a credential file at `~/.olimpia/<IP>.json`.

### Method 1: Paste JSON in the config flow (recommended)

1. Open the credential file: `cat ~/.olimpia/<IP>.json`
2. Copy its full contents
3. In Home Assistant: **Settings > Devices & Services > Add Integration > Olimpia Splendid Unico**
4. Choose **"Configured device (enter IP)"**
5. Enter the device IP and paste the JSON into the **"Credentials JSON"** field

### Method 2: Copy file to HA machine

Copy the credential file to the `~/.olimpia/` directory on the machine running Home Assistant, then use the Manual IP option (leave the credentials JSON field empty).

| HA Installation | Credential path | Copy method |
|-|-|-|
| HA Core (venv) | `~/.olimpia/<IP>.json` (home of HA user) | `cp` or `scp` |
| Docker | `/root/.olimpia/<IP>.json` inside container | `docker cp file.json homeassistant:/root/.olimpia/` |
| HAOS | `/root/.olimpia/<IP>.json` inside HA container | Use SSH addon or `ha ssh` |
| Supervised | `/root/.olimpia/<IP>.json` inside HA container | `docker cp` to `homeassistant` container |

## Credential file format

The tool generates a JSON file with this structure:

```json
{
  "host": "192.168.1.100",
  "user_id": "olimpia-python",
  "user_hash": "...",
  "user_counter": 0,
  "device_uid": "...",
  "crypto": {
    "shared_secret": "...",
    "ltk": "...",
    "session_key": "...",
    "iv_head": "...",
    "rnd_host": "...",
    "rnd_device": "...",
    "counter": 12
  }
}
```

## Notes

- BLE pairing creates an independent user slot on the device. It can coexist with the official app.
- If the device changes IP (e.g., after a router reboot), update the IP in the HA integration settings. It is recommended to assign a static IP via DHCP reservation.
- Default device PIN: `12345678` (verify on the label of your unit).
