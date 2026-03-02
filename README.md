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
- **Local polling** (30 s) with automatic reconnect and keepalive
- **BLE setup flow**: scan, ECDH pairing, WiFi provisioning — all from the HA config UI
- **Manual IP** setup with existing credentials

## Requirements

- Home Assistant **2024.8.0** or newer
- The Unico unit must be on the same LAN as your HA instance (TCP port 2000)
- For BLE setup: a Bluetooth adapter accessible to HA

## Installation

### HACS (recommended)

1. Open HACS in Home Assistant
2. Click the three-dot menu → **Custom repositories**
3. Add `https://github.com/Daneel87/ha-olimpia-splendid-unico` with category **Integration**
4. Search for "Olimpia Splendid Unico" and install
5. Restart Home Assistant

### Manual

1. Copy `custom_components/olimpia_splendid/` into `/homeassistant/custom_components/`
2. Restart Home Assistant

## Configuration

After installation, go to **Settings → Devices & Services → Add Integration** and search for **Olimpia Splendid Unico**.

You will be offered two setup paths:

- **BLE Setup (recommended)**: the easiest and most automated method. Scan for nearby Unico devices via Bluetooth, enter the PIN (printed on the unit), complete ECDH pairing, configure WiFi, and the integration will automatically discover the device IP. No manual steps required beyond entering PIN and WiFi credentials.
- **Manual IP**: enter the device IP address directly. Credentials are imported from `~/.olimpia/` if available, or you can pair first using the standalone CLI.

## Compatibility

Tested on **Olimpia Splendid Unico Pro** with **B1015 WiFi board**. Should work with all Unico models equipped with the same B1015 board (same protocol and app — Olimpia Splendid Unico v1.0.9).

## License

MIT
