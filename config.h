#pragma once

// ============================================================
//  GhostWave ESP32 Firmware — Authorized Pentest Use Only
// ============================================================

// ── Hardware ─────────────────────────────────────────────────
#define SERIAL_BAUD       115200
#define LED_PIN           2       // Built-in LED (most ESP32 devboards)

// Optional SSD1306 OLED (comment out to disable)
// #define USE_OLED
// #define OLED_SDA        21
// #define OLED_SCL        22
// #define OLED_ADDR       0x3C

// ── WiFi Defaults ────────────────────────────────────────────
#define WIFI_SCAN_CHANNEL_MIN   1
#define WIFI_SCAN_CHANNEL_MAX   13
#define DEAUTH_REASON_CODE      0x0007  // Class 3 frame from nonassoc STA
#define DEAUTH_BURST            10      // Frames per burst
#define BEACON_SPAM_COUNT       20      // Fake APs per spam run
#define CHANNEL_HOP_INTERVAL_MS 200     // Sniffer channel hop speed

// ── Bluetooth Defaults ───────────────────────────────────────
#define BLE_SCAN_DURATION_SEC   5
#define BLE_ADV_INTERVAL_MS     200

// ── Defense Thresholds ───────────────────────────────────────
#define DEAUTH_DETECT_THRESHOLD 5    // deauth frames / window → alert
#define DEAUTH_DETECT_WINDOW_MS 1000

// ── Build Info ───────────────────────────────────────────────
#define FW_NAME    "GhostWave"
#define FW_VERSION "1.0.0"
