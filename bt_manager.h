#pragma once
#include <Arduino.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#include <BLEServer.h>
#include <BLEAdvertising.h>
#include "config.h"

// ── Structs ──────────────────────────────────────────────────

struct BLERecord {
  char     address[18];
  char     name[32];
  int8_t   rssi;
  uint16_t appearance;
  bool     connectable;
};

// ── BT Manager Class ─────────────────────────────────────────

class BTManager {
public:
  void begin();
  void stop();

  // ── BLE Scanning ──────────────────────────────────────────
  void bleScan(uint8_t durationSec = BLE_SCAN_DURATION_SEC);
  void printBLEDevices();

  // ── BLE Advertising / Spoof ───────────────────────────────
  // Advertise as a custom device (Apple, Google, Samsung proximity beacon, etc.)
  void bleAdvertiseCustom(const char* name, uint16_t appearance = 0x0000);
  void bleSpamAppleProximity();   // flood iOS notification popups
  void bleSpamGoogleFastPair();   // flood Android FastPair dialogs
  void stopBLEAdvertise();

  // ── BLE Jammer (channel saturation) ──────────────────────
  // Saturates the three BLE advertising channels (37/38/39)
  // by flooding advertisement PDUs
  void bleJammerStart();
  void bleJammerStop();
  void bleJammerTick();

  // ── GATT Server ───────────────────────────────────────────
  // Spin up a basic GATT server to accept and log connections
  void startGATTServer();
  void stopGATTServer();

  // ── State ─────────────────────────────────────────────────
  BLERecord bleDevices[64];
  uint8_t   bleDeviceCount = 0;

private:
  BLEScan*        _pScan      = nullptr;
  BLEServer*      _pServer    = nullptr;
  BLEAdvertising* _pAdv       = nullptr;
  bool            _jamming    = false;
  bool            _advertising = false;

  // Apple Proximity beacon payload for popup spoof
  static const uint8_t kAppleAirDropPayload[];
  static const uint8_t kAppleContinuityPayload[];
};

extern BTManager btMgr;
