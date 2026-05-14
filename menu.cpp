#include "menu.h"
#include "wifi_manager.h"
#include "bt_manager.h"

static String _cmdBuf = "";

void printBanner() {
  Serial.println();
  Serial.println("  ╔════════════════════════════════════════╗");
  Serial.println("  ║   GhostWave ESP32 Pentest Firmware     ║");
  Serial.printf( "  ║   v%-36s║\n", FW_VERSION "  ");
  Serial.println("  ║   FOR AUTHORIZED TESTING ONLY          ║");
  Serial.println("  ╚════════════════════════════════════════╝");
  Serial.println();
}

void printHelp() {
  Serial.println("  ┌─ WiFi ─────────────────────────────────────────────────────┐");
  Serial.println("  │  scan                  Scan for nearby APs                 │");
  Serial.println("  │  list                  Show last scan results               │");
  Serial.println("  │  sniff                 Start promiscuous sniffer            │");
  Serial.println("  │  sniff stop            Stop sniffer                         │");
  Serial.println("  │                                                             │");
  Serial.println("  │  [RED TEAM]                                                 │");
  Serial.println("  │  deauth <idx> [all]    Deauth AP from scan list (all=bcast) │");
  Serial.println("  │  deauth <bssid> <mac> <ch>  Deauth specific client         │");
  Serial.println("  │  beacon <ch> [count]   Beacon spam on channel              │");
  Serial.println("  │  probe  <ch> [count]   Probe flood on channel              │");
  Serial.println("  │  evil <ssid> [pass] [ch]  Start evil twin AP               │");
  Serial.println("  │  evil stop             Stop evil twin                       │");
  Serial.println("  │                                                             │");
  Serial.println("  │  [BLUE TEAM]                                                │");
  Serial.println("  │  detect                Start deauth/disassoc detector       │");
  Serial.println("  │  detect stop           Stop detector                        │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");
  Serial.println("  ┌─ Bluetooth ─────────────────────────────────────────────────┐");
  Serial.println("  │  blescan [secs]        BLE device scan                      │");
  Serial.println("  │  blelist               Print BLE scan results               │");
  Serial.println("  │  bleadv <name>         Advertise as BLE device              │");
  Serial.println("  │  bleadv stop           Stop BLE advertising                 │");
  Serial.println("  │  applespam             Apple proximity popup spam           │");
  Serial.println("  │  gpspam                Google Fast Pair spam                │");
  Serial.println("  │  gatt                  Start GATT server                    │");
  Serial.println("  │  gatt stop             Stop GATT server                     │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");
  Serial.println("  ┌─ System ───────────────────────────────────────────────────┐");
  Serial.println("  │  info                  Device info                          │");
  Serial.println("  │  help / ?              Show this menu                       │");
  Serial.println("  └─────────────────────────────────────────────────────────────┘");
  Serial.println();
}

static bool parseMAC(const char* str, uint8_t* mac) {
  return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

static void handleCommand(const String& raw) {
  String line = raw;
  line.trim();
  if (line.length() == 0) return;

  // tokenize
  const int MAX_ARGS = 6;
  String args[MAX_ARGS];
  int argc = 0;
  int start = 0;
  for (int i = 0; i <= (int)line.length() && argc < MAX_ARGS; i++) {
    if (i == (int)line.length() || line[i] == ' ') {
      if (i > start) args[argc++] = line.substring(start, i);
      start = i + 1;
    }
  }
  if (argc == 0) return;
  String cmd = args[0];
  cmd.toLowerCase();

  // ── WiFi ────────────────────────────────────────────────────

  if (cmd == "scan") {
    wifiMgr.scanNetworks();
    wifiMgr.printNetworks();
  }
  else if (cmd == "list") {
    wifiMgr.printNetworks();
  }
  else if (cmd == "sniff") {
    if (argc >= 2 && args[1] == "stop") {
      wifiMgr.stopPromiscuousSniffer();
    } else {
      wifiMgr.startPromiscuousSniffer();
    }
  }

  // deauth <index> [all] OR deauth <bssid> <clientmac> <ch>
  else if (cmd == "deauth") {
    if (argc < 2) { Serial.println("Usage: deauth <idx> [all] | deauth <bssid> <mac> <ch>"); return; }

    uint8_t apBSSID[6], targetMAC[6];
    uint8_t ch = 6;

    // Try to parse first arg as MAC
    if (parseMAC(args[1].c_str(), apBSSID)) {
      if (argc < 4 || !parseMAC(args[2].c_str(), targetMAC)) {
        Serial.println("Usage: deauth <ap_bssid> <client_mac> <channel>");
        return;
      }
      ch = args[3].toInt();
      wifiMgr.deauthAttack(apBSSID, targetMAC, ch);
    } else {
      // Index-based
      int idx = args[1].toInt();
      if (idx < 0 || idx >= wifiMgr.networkCount) {
        Serial.printf("Invalid index. Run 'scan' first (0-%d).\n", wifiMgr.networkCount - 1);
        return;
      }
      memcpy(apBSSID, wifiMgr.networks[idx].bssid, 6);
      ch = wifiMgr.networks[idx].channel;
      bool bcast = (argc >= 3 && args[2] == "all");
      wifiMgr.deauthAttack(apBSSID, bcast ? nullptr : nullptr, ch);
    }
  }

  else if (cmd == "beacon") {
    uint8_t ch    = argc >= 2 ? args[1].toInt() : 6;
    uint16_t cnt  = argc >= 3 ? args[2].toInt() : BEACON_SPAM_COUNT;
    if (ch < 1 || ch > 13) { Serial.println("Channel must be 1-13."); return; }
    wifiMgr.beaconSpam(ch, cnt);
  }

  else if (cmd == "probe") {
    uint8_t ch   = argc >= 2 ? args[1].toInt() : 6;
    uint16_t cnt = argc >= 3 ? args[2].toInt() : 50;
    if (ch < 1 || ch > 13) { Serial.println("Channel must be 1-13."); return; }
    wifiMgr.probeFlood(ch, cnt);
  }

  else if (cmd == "evil") {
    if (argc >= 2 && args[1] == "stop") {
      wifiMgr.stopEvilTwin();
    } else if (argc >= 2) {
      const char* ssid = args[1].c_str();
      const char* pass = argc >= 3 ? args[2].c_str() : nullptr;
      uint8_t ch       = argc >= 4 ? args[3].toInt() : 1;
      wifiMgr.evilTwin(ssid, pass, ch);
    } else {
      Serial.println("Usage: evil <ssid> [password] [channel]");
    }
  }

  else if (cmd == "detect") {
    if (argc >= 2 && args[1] == "stop") {
      wifiMgr.stopDeauthDetector();
      Serial.printf("[BLUE TEAM] Captured %d deauth/disassoc frames.\n", wifiMgr.deauthFrameCount());
    } else {
      wifiMgr.startDeauthDetector();
    }
  }

  // ── Bluetooth ────────────────────────────────────────────────

  else if (cmd == "blescan") {
    uint8_t dur = argc >= 2 ? args[1].toInt() : BLE_SCAN_DURATION_SEC;
    btMgr.bleScan(dur);
  }
  else if (cmd == "blelist") {
    btMgr.printBLEDevices();
  }
  else if (cmd == "bleadv") {
    if (argc >= 2 && args[1] == "stop") {
      btMgr.stopBLEAdvertise();
    } else if (argc >= 2) {
      btMgr.bleAdvertiseCustom(args[1].c_str());
    } else {
      Serial.println("Usage: bleadv <name> | bleadv stop");
    }
  }
  else if (cmd == "applespam") {
    btMgr.bleSpamAppleProximity();
  }
  else if (cmd == "gpspam") {
    btMgr.bleSpamGoogleFastPair();
  }
  else if (cmd == "gatt") {
    if (argc >= 2 && args[1] == "stop") {
      btMgr.stopGATTServer();
    } else {
      btMgr.startGATTServer();
    }
  }

  // ── System ───────────────────────────────────────────────────

  else if (cmd == "info") {
    Serial.printf("  Firmware : %s v%s\n", FW_NAME, FW_VERSION);
    Serial.printf("  Chip     : %s rev%d\n", ESP.getChipModel(), ESP.getChipRevision());
    Serial.printf("  CPU MHz  : %d\n", ESP.getCpuFreqMHz());
    Serial.printf("  Free RAM : %d bytes\n", ESP.getFreeHeap());
    Serial.printf("  Flash    : %d MB\n", ESP.getFlashChipSize() / (1024*1024));
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    Serial.printf("  WiFi MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
      mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    esp_read_mac(mac, ESP_MAC_BT);
    Serial.printf("  BT MAC   : %02X:%02X:%02X:%02X:%02X:%02X\n",
      mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    Serial.printf("  Uptime   : %lu ms\n", millis());
  }
  else if (cmd == "help" || cmd == "?") {
    printHelp();
  }
  else {
    Serial.printf("Unknown command: '%s'  — type 'help' for command list.\n", cmd.c_str());
  }
}

void menuInit() {
  Serial.print("> ");
}

void menuTick() {
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      Serial.println();
      handleCommand(_cmdBuf);
      _cmdBuf = "";
      Serial.print("> ");
    } else if (c == 0x7F || c == '\b') { // backspace
      if (_cmdBuf.length() > 0) {
        _cmdBuf.remove(_cmdBuf.length() - 1);
        Serial.print("\b \b");
      }
    } else {
      _cmdBuf += c;
      Serial.print(c); // echo
    }
  }
}
