# Olimpia Splendid Unico

[![HACS Validation](https://github.com/Daneel87/ha-olimpia-splendid-unico/actions/workflows/validate.yml/badge.svg)](https://github.com/Daneel87/ha-olimpia-splendid-unico/actions/workflows/validate.yml)
[![Hassfest](https://github.com/Daneel87/ha-olimpia-splendid-unico/actions/workflows/hassfest.yml/badge.svg)](https://github.com/Daneel87/ha-olimpia-splendid-unico/actions/workflows/hassfest.yml)

Custom [Home Assistant](https://www.home-assistant.io/) integration for **Olimpia Splendid Unico** air conditioners via **local TCP** control (no cloud required). Optional BLE setup for initial pairing and WiFi configuration.

## Features

- **HVAC modes**: Heat, Cool, Dry, Fan Only, Auto
- **Fan speed**: Low, Mid, High, Auto
- **Swing**: On / Off
- **Target temperature** control
- **Room temperature** reading
- **Scheduler** switch entity
- **Local polling** (30s) with automatic reconnect and keepalive
- **BLE setup flow**: scan, ECDH pairing, WiFi provisioning — all from the HA config UI
- **Manual IP** setup with credential paste or file import

## Requirements

- Home Assistant **2024.8.0** or newer
- The Unico unit must be on the same LAN as your HA instance (TCP port 2000)
- For BLE setup: a Bluetooth adapter accessible to HA

## Installation

### HACS (recommended)

1. Open HACS in Home Assistant
2. Click the three-dot menu > **Custom repositories**
3. Add `https://github.com/Daneel87/ha-olimpia-splendid-unico` with category **Integration**
4. Search for "Olimpia Splendid Unico" and install
5. Restart Home Assistant

### Manual

1. Copy `custom_components/olimpia_splendid/` into your HA `custom_components/` directory
2. Restart Home Assistant

## Configuration

Go to **Settings > Devices & Services > Add Integration** and search for **Olimpia Splendid Unico**. You will be offered two setup paths:

### Option A: BLE Setup (recommended)

The easiest method if your HA instance has access to a Bluetooth adapter.

1. Choose **"New device — BLE setup"**
2. The integration scans for nearby Unico devices via Bluetooth
3. Select your device from the list (it appears as "OL01")
4. Enter:
   - **Device PIN**: printed on a label on the unit (default: `51506160`)
   - **WiFi SSID**: your network name
   - **WiFi Password**: your network password
5. Wait for pairing to complete (up to 60 seconds)
6. The integration automatically discovers the device IP — done!

### Option B: External BLE Pairing + Manual IP

Use this method when HA does not have Bluetooth access (VM, Docker without BT passthrough, remote machine, etc.).

#### Step 1: Run the BLE pairing tool

On a machine with a Bluetooth adapter (laptop, Raspberry Pi, etc.):

```bash
# Clone the repository (or download just the tools/ directory)
git clone https://github.com/Daneel87/ha-olimpia-splendid-unico.git
cd ha-olimpia-splendid-unico/tools

# Install dependencies
pip install -r requirements.txt

# Scan for your device
python olimpia_ble.py scan

# Run full setup (pairing + WiFi)
python olimpia_ble.py setup <MAC_ADDRESS> --pin <PIN> --ssid "YourWiFi" --password "YourPassword"
```

On success, the tool saves credentials to `~/.olimpia/<IP>.json` and prints the device IP.

See [tools/README.md](tools/README.md) for the full command reference.

#### Step 2: Add the integration in HA

1. Go to **Settings > Devices & Services > Add Integration > Olimpia Splendid Unico**
2. Choose **"Configured device (enter IP)"**
3. Enter the device IP address
4. **Paste the credentials JSON** (recommended): open `~/.olimpia/<IP>.json` from the machine where you ran the tool, copy its full contents, and paste it into the "Credentials JSON" field
5. Alternatively, leave the credentials field empty if you've copied the file to the HA machine (see [tools/README.md](tools/README.md#method-2-copy-file-to-ha-machine) for paths)

### Post-setup

- **Assign a static IP** to the device via your router's DHCP reservation. This prevents the IP from changing and the integration losing contact with the unit.
- Verify the integration is working: check that the climate entity shows the current room temperature.

## Troubleshooting

### BLE scan finds no devices

- Ensure the Bluetooth adapter is working: `hcitool dev` should list it
- Move closer to the unit (BLE range is ~10m)
- The device appears as "OL01" — try `python olimpia_ble.py scan --name OL01`
- Some adapters need a reset: `sudo hciconfig hci0 reset`

### BLE pairing fails

- Check the PIN (printed on the unit label, default: `51506160`)
- The device allows limited concurrent users — try a factory reset of the WiFi board if needed
- Use `-v` for verbose output to diagnose which pairing step fails
- Retry: BLE can be flaky with weak signal, the tool retries automatically up to 3 times

### "No credentials found" on Manual IP

- Ensure you ran the BLE pairing tool successfully first
- Paste the JSON content from `~/.olimpia/<IP>.json` into the "Credentials JSON" field
- If loading from disk: the file must be at `~/.olimpia/<IP>.json` on the machine running HA (where `~` is the home directory of the HA process — `/root/` for HAOS/Docker)

### Device shows as unavailable

- Check that the device is on the same network and reachable: `ping <IP>`
- TCP port 2000 must be accessible
- After a router reboot, the device may get a new IP — update the integration or set up DHCP reservation

## Compatibility

Tested on **Olimpia Splendid Unico Pro** with **B1015 WiFi board**. Should work with all Unico models equipped with the same B1015 board (same protocol and app — Olimpia Splendid Unico v1.0.9).

## Protocol Documentation

The BLE and WiFi protocol is documented in [PROTOCOL_BLE_WIFI.md](PROTOCOL_BLE_WIFI.md) for those interested in the technical details.

## License

MIT
