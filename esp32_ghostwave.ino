/**
 *  Wave — ESP32 Penetration Testing Firmware
 *  ================================================
 *  LEGAL NOTICE: This firmware is intended exclusively for
 *  authorized security research and penetration testing on
 *  networks and devices you own or have explicit written
 *  permission to test. Unauthorized use against third-party
 *  networks is illegal under the Computer Fraud and Abuse Act
 *  (US), Computer Misuse Act (UK), and equivalent laws
 *  worldwide. The authors accept no liability for misuse.
 *
 *  Inspired by ESP32 Marauder (justcallmekoko)
 *  Build target: ESP32 (Arduino core 2.x, ESP-IDF 4.x)
 *
 *  Required libraries (install via Arduino Library Manager):
 *    - ESP32 Arduino core (espressif/arduino-esp32) >= 2.0.0
 *    - NimBLE or standard BLEDevice (included in core)
 *
 *  Wiring:
 *    LED_PIN (GPIO 2) — built-in LED on most devboards
 *    Optional OLED: enable USE_OLED in config.h
 */

#include "config.h"
#include "wifi_manager.h"
#include "bt_manager.h"
#include "menu.h"

// ── Status LED ───────────────────────────────────────────────

static void ledBlink(int times, int ms = 80) {
  for (int i = 0; i < times; i++) {
    digitalWrite(LED_PIN, HIGH); delay(ms);
    digitalWrite(LED_PIN, LOW);  delay(ms);
  }
}

// ── Setup ─────────────────────────────────────────────────────

void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);

  Serial.begin(SERIAL_BAUD);
  delay(500);

  printBanner();

  Serial.println("[*] Initializing WiFi stack...");
  wifiMgr.begin();
  ledBlink(1);

  Serial.println("[*] Initializing Bluetooth stack...");
  btMgr.begin();
  ledBlink(2);

  Serial.println("[*] Ready.\n");
  printHelp();
  menuInit();
}

// ── Loop ──────────────────────────────────────────────────────

void loop() {
  // Process serial commands
  menuTick();

  // Keep promiscuous sniffer channel-hopping
  wifiMgr.snifferTick();

  // Status heartbeat on LED
  static uint32_t lastBeat = 0;
  if (millis() - lastBeat > 2000) {
    digitalWrite(LED_PIN, HIGH); delay(10); digitalWrite(LED_PIN, LOW);
    lastBeat = millis();
  }
}
