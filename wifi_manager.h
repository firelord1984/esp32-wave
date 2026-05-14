#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "config.h"

// ── Structs ──────────────────────────────────────────────────

struct APRecord {
  uint8_t  bssid[6];
  char     ssid[33];
  int8_t   rssi;
  uint8_t  channel;
  wifi_auth_mode_t auth;
};

struct ClientRecord {
  uint8_t  mac[6];
  uint8_t  ap_bssid[6];
  int8_t   rssi;
};

// ── WiFi Manager Class ───────────────────────────────────────

class WiFiManager {
public:
  // Lifecycle
  void begin();
  void stop();

  // ── Scanning ─────────────────────────────────────────────
  void scanNetworks();
  void printNetworks();
  void startPromiscuousSniffer();
  void stopPromiscuousSniffer();
  void snifferTick();           // call in loop() while sniffing

  // ── Red Team ─────────────────────────────────────────────
  // Deauthenticate a client from an AP (or broadcast deauth all)
  // target_mac = client MAC, nullptr = broadcast (FF:FF:FF:FF:FF:FF)
  void deauthAttack(uint8_t ap_bssid[6], uint8_t* target_mac, uint8_t channel, uint16_t rounds = 0);

  // Flood channel with fake beacon frames
  void beaconSpam(uint8_t channel, uint16_t count = BEACON_SPAM_COUNT);

  // Send 802.11 probe requests to force AP response logs
  void probeFlood(uint8_t channel, uint16_t count = 50);

  // Spin up a rogue / evil-twin AP
  bool evilTwin(const char* ssid, const char* password = nullptr, uint8_t channel = 1);
  void stopEvilTwin();

  // ── Blue Team ─────────────────────────────────────────────
  void startDeauthDetector();
  void stopDeauthDetector();
  bool deauthDetectorRunning() { return _detecting; }
  uint32_t deauthFrameCount()  { return _deauthCount; }
  void resetDeauthCount()      { _deauthCount = 0; }

  // ── Helpers ───────────────────────────────────────────────
  void setChannel(uint8_t ch);
  void printMAC(const uint8_t* mac);
  static const char* authModeName(wifi_auth_mode_t mode);

  // ── State ─────────────────────────────────────────────────
  APRecord     networks[32];
  uint8_t      networkCount = 0;
  ClientRecord clients[64];
  uint8_t      clientCount  = 0;

private:
  bool    _sniffing   = false;
  bool    _detecting  = false;
  uint8_t _channel    = 1;

  volatile uint32_t _deauthCount  = 0;
  volatile uint32_t _deauthWindow = 0;

  static void _promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
  static void _detectorCallback(void* buf, wifi_promiscuous_pkt_type_t type);

  void _sendRawFrame(const uint8_t* frame, size_t len);
  void _buildDeauthFrame(uint8_t* buf, const uint8_t* dst, const uint8_t* src, const uint8_t* bssid, uint16_t reason);
  void _buildBeaconFrame(uint8_t* buf, size_t& len, const char* ssid, uint8_t channel, const uint8_t* bssid);

  static WiFiManager* _instance;  // for static callbacks
};

extern WiFiManager wifiMgr;
