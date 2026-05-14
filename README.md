# GhostWave — ESP32 Penetration Testing Firmware

> **⚠️ AUTHORIZED USE ONLY** — Only test networks and devices you own or have
> explicit written permission to test. Unauthorized use is illegal in most
> jurisdictions (CFAA, Computer Misuse Act, etc.).

---

## Hardware Requirements

| Component | Notes |
|-----------|-------|
| ESP32 DevKit (any variant) | ESP32-WROOM-32 recommended |
| USB cable | For flashing & serial console |
| Optional: SSD1306 OLED (128x64) | Enable `USE_OLED` in `config.h` |

The ESP32 has:
- **2.4 GHz 802.11 b/g/n** WiFi with promiscuous/raw TX support
- **Bluetooth 4.2** (Classic + BLE) dual-mode
- Dual-core 240 MHz Xtensa LX6

---

## Build & Flash

### Arduino IDE

1. Install **Arduino IDE 2.x**
2. Add ESP32 board package:  
   `File → Preferences → Additional Board URLs`:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Install **esp32 by Espressif** via Boards Manager
4. Open `esp32_ghostwave.ino`
5. Select: `Tools → Board → ESP32 Dev Module`
6. Set `Partition Scheme → Minimal SPIFFS (1.9MB APP)`
7. Flash speed: `921600` baud
8. Upload

### PlatformIO

```ini
[env:esp32dev]
platform  = espressif32
board     = esp32dev
framework = arduino
monitor_speed = 115200
board_build.partitions = min_spiffs.csv
```

---

## Serial Console

Connect at **115200 baud** (any terminal: Arduino Serial Monitor, PuTTY, screen, minicom).

---

## Command Reference

### WiFi

| Command | Description |
|---------|-------------|
| `scan` | Active scan — lists nearby APs with BSSID, channel, RSSI, encryption |
| `list` | Re-print last scan results |
| `sniff` | Start promiscuous sniffer (channel-hops 1–13, logs clients + probes) |
| `sniff stop` | Stop sniffer |

**Red Team**

| Command | Description |
|---------|-------------|
| `deauth <idx>` | Deauth broadcast at AP from scan list |
| `deauth <idx> all` | Same — explicit broadcast |
| `deauth <ap_bssid> <client_mac> <ch>` | Targeted deauth by MAC |
| `beacon <ch> [count]` | Flood channel with `count` fake SSIDs (default 20) |
| `probe <ch> [count]` | Send random probe requests (default 50) |
| `evil <ssid> [pass] [ch]` | Start evil-twin open/WPA2 AP |
| `evil stop` | Tear down evil twin |

**Blue Team**

| Command | Description |
|---------|-------------|
| `detect` | Start deauth/disassoc frame detector — alerts on storms |
| `detect stop` | Stop detector, print frame count |

### Bluetooth / BLE

| Command | Description |
|---------|-------------|
| `blescan [secs]` | Passive BLE scan (default 5s) |
| `blelist` | Print BLE scan results |
| `bleadv <name>` | Advertise ESP32 as a BLE peripheral |
| `bleadv stop` | Stop advertising |
| `applespam` | Apple Continuity protocol proximity popup research |
| `gpspam` | Google Fast Pair popup research |
| `gatt` | Start GATT server, log connecting clients |
| `gatt stop` | Stop GATT server |

### System

| Command | Description |
|---------|-------------|
| `info` | Chip model, MAC addresses, free RAM, uptime |
| `help` / `?` | Print command reference |

---

## Architecture

```
esp32_ghostwave/
├── esp32_ghostwave.ino   ← Setup/loop entry point
├── config.h              ← All tuneable constants
├── wifi_manager.h/.cpp   ← WiFi scan, raw TX, sniffer, attacks, detector
├── bt_manager.h/.cpp     ← BLE scan, advertising, GATT server
└── menu.h/.cpp           ← Serial command parser
```

### Extending

- Add a new **WiFi module**: implement in `wifi_manager.cpp`, expose method in header, add a command branch in `menu.cpp`
- Add a **display**: enable `USE_OLED` in `config.h` and add Adafruit_SSD1306 calls
- Add a **web UI**: enable `WiFi.softAP()` + `WebServer` on the evil twin to serve a captive portal

---

## Known Limitations

- Raw 802.11 TX (`esp_wifi_80211_tx`) requires STA mode with promiscuous enabled
- BLE and WiFi share the same 2.4 GHz radio — some operations can't run simultaneously
- Deauth attacks only work on networks using WPA/WPA2 (not WPA3 PMF-protected networks)
- Apple proximity popups require iOS < 17.2 (patched in later versions)

---

## Legal & Ethics Reminder

This firmware is for:
- Your own home/lab networks
- CTF competitions
- Authorized red team engagements
- Security research in a controlled RF environment

**Not for use against any network or device without written permission.**
