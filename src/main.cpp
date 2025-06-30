#include <Preferences.h>
#include <WiFi.h>
#include <BLEDevice.h>
#include <BLEServer.h>
#include <BLEUtils.h>
#include <BLE2902.h>
#define ENABLE_USER_AUTH
#define ENABLE_DATABASE
#include <FirebaseClient.h>
#include "ExampleFunctions.h"


// BLE إعدادات
BLEServer* pServer = NULL;
BLECharacteristic* pCharacteristic = NULL;
BLECharacteristic *pMacCharacteristic = NULL;
Preferences preferences;
// MAC عنوان
String macAddress = "";
#define SERVICE_UUID        "4fafc201-1fb5-459e-8fcc-c5c9c331914b"
#define WIFI_UUID "beb5483e-36e1-4688-b7f5-ea07361b26a8"
#define MAC_UUID "abcdef12-3456-7890-abcd-ef1234567890"
#define PASSKEY 999999

// configure firebase
#define API_KEY "AIzaSyAckLpD06AhyjlVdbTHiXTCstclomOipHQ"
#define USER_EMAIL "anssobhi1996@gmail.com"
#define USER_PASSWORD "123456"
#define DATABASE_URL "https://rtdb-3efa6-default-rtdb.firebaseio.com"

void processData(AsyncResult &aResult);

SSL_CLIENT ssl_client;
using AsyncClient = AsyncClientClass;
AsyncClient aClient(ssl_client);

UserAuth user_auth(API_KEY, USER_EMAIL, USER_PASSWORD, 3000 /* expire period in seconds (<3600) */);
FirebaseApp app;
RealtimeDatabase Database;
AsyncResult databaseResult;

// Timer variables for sending data every 10 seconds
unsigned long lastSendTime = 0;
const unsigned long sendInterval = 5000; // 10 seconds in milliseconds

#define LED_PIN 2

// وظيفة الاتصال بالشبكة Wi-Fi
void connectToWiFi(String ssid, String password) {
  WiFi.disconnect(true);
  WiFi.begin(ssid.c_str(), password.c_str());

  Serial.print("Connecting to WiFi...");
  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries < 10) {
    delay(1000);
    Serial.print(".");
    retries++;
  }

  Serial.println();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("Connected! IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("Failed to connect to WiFi.");
  }
}

// Callback لاستقبال بيانات Wi-Fi
class WifiCharacteristicCallback : public BLECharacteristicCallbacks {
    void onWrite(BLECharacteristic *pCharacteristic) {
      std::string value = pCharacteristic->getValue();
      if (value.length() > 0) {
        Serial.print("Received WiFi Credentials: ");
        Serial.println(value.c_str());

        int sep = value.find(":");
        if (sep != std::string::npos) {
          String ssid = String(value.substr(0, sep).c_str());
          String pass = String(value.substr(sep + 1).c_str());

          preferences.begin("wifi", false);
          preferences.putString("ssid", ssid);
          preferences.putString("password", pass);
          preferences.end();

          Serial.printf("Saved SSID: %s\n", ssid.c_str());
          Serial.printf("Saved PASS: %s\n", pass.c_str());

          connectToWiFi(ssid, pass);
        } else {
          Serial.println("Invalid format! Use SSID|PASSWORD");
        }
      }
    }
};

// BLE Callbacks
class ServerCallback: public BLEServerCallbacks {
    void onConnect(BLEServer* pServer) {
      Serial.println(" - ServerCallback - onConnect");
    };

    void onDisconnect(BLEServer* pServer) {
      Serial.println(" - ServerCallback - onDisconnect");
      BLEDevice::startAdvertising();
    }
};

class SecurityCallback : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() {
    return PASSKEY;
  }

  void onPassKeyNotify(uint32_t pass_key) {}

  bool onConfirmPIN(uint32_t pass_key) {
    Serial.printf("Confirming Passkey: %06d\n", pass_key);
    return true;
  }

  bool onSecurityRequest() {
    return true;
  }

  void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl) {
    if (cmpl.success) {
      Serial.println("   - SecurityCallback - Authentication Success");
    } else {
      Serial.println("   - SecurityCallback - Authentication Failure*");
      pServer->removePeerDevice(pServer->getConnId(), true);
      BLEDevice::startAdvertising();
    }
  }
};

// إعداد الأمان BLE
void bleSecurity() {
  esp_ble_auth_req_t auth_req = ESP_LE_AUTH_REQ_SC_MITM_BOND;
  esp_ble_io_cap_t iocap = ESP_IO_CAP_OUT;
  uint8_t key_size = 16;
  uint8_t init_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint8_t rsp_key = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK;
  uint32_t passkey = PASSKEY;
  uint8_t auth_option = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_DISABLE;

  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth_req, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE, &iocap, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE, &key_size, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &auth_option, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY, &init_key, sizeof(uint8_t));
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY, &rsp_key, sizeof(uint8_t));
}

// إعداد BLE
void bleInit() {
  BLEDevice::init("BLE-Secure-Server");
  BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT);
  BLEDevice::setSecurityCallbacks(new SecurityCallback());

  pServer = BLEDevice::createServer();
  pServer->setCallbacks(new ServerCallback());

  BLEService *pService = pServer->createService(SERVICE_UUID);
  
  // إنشاء خاصية Wi-Fi
  pCharacteristic = pService->createCharacteristic(
    WIFI_UUID,
    BLECharacteristic::PROPERTY_READ |
    BLECharacteristic::PROPERTY_WRITE |
    BLECharacteristic::PROPERTY_NOTIFY
  );
  pCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED);
  pCharacteristic->setCallbacks(new WifiCharacteristicCallback());
  BLEDescriptor* wifides = new BLEDescriptor(BLEUUID((uint16_t)0x2901));
  wifides->setValue("wifi-credential");
  pCharacteristic->addDescriptor(wifides);
  //pCharacteristic->addDescriptor(new BLE2902());
  // إنشاء خاصية MAC
  pMacCharacteristic = pService->createCharacteristic(
    MAC_UUID,
    BLECharacteristic::PROPERTY_READ
  );
  pMacCharacteristic->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED | ESP_GATT_PERM_WRITE_ENCRYPTED);
  pMacCharacteristic->setValue(macAddress.c_str());
  pService->start();

  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(false);
  pAdvertising->setMinPreferred(0x06);  // optional
  pAdvertising->setMaxPreferred(0x12);  // optional

  BLEDevice::startAdvertising();

  bleSecurity();
}

void setup() {
  Serial.begin(115200);
  preferences.begin("wifi", true);
  String ssid = preferences.getString("ssid", "");
  String pass = preferences.getString("password", "");
  preferences.end();
  
  WiFi.mode(WIFI_STA);
  macAddress = WiFi.macAddress();
  Serial.print("MAC Address: ");
  Serial.println(macAddress);
  bleInit();

  if (ssid != "") {
    connectToWiFi(ssid, pass);
  }
   //set_ssl_client_insecure_and_buffer(ssl_client);
  ssl_client.setInsecure();
  //ssl_client.setConnectionTimeout(1000);
  ssl_client.setHandshakeTimeout(5);

    Serial.println("Initializing app...");
    initializeApp(aClient, app, getAuth(user_auth), auth_debug_print, "🔐 authTask");

    app.getApp<RealtimeDatabase>(Database);
    Database.url(DATABASE_URL);

}

void loop() {
    app.loop();
  processData(databaseResult);

  if (app.ready() && millis() - lastSendTime > sendInterval) {
    lastSendTime = millis();

    // قراءة قيمة مرة واحدة من Firebase
    Database.get(aClient,"/ledStatus",processData);
  }
}

void processData(AsyncResult &aResult)
{
    // Exits when no result available when calling from the loop.
    if (!aResult.isResult())
        return;

    if (aResult.isEvent())
    {
        Firebase.printf("Event task: %s, msg: %s, code: %d\n", aResult.uid().c_str(), aResult.eventLog().message().c_str(), aResult.eventLog().code());
    }

    if (aResult.isDebug())
    {
        Firebase.printf("Debug task: %s, msg: %s\n", aResult.uid().c_str(), aResult.debug().c_str());
    }

    if (aResult.isError())
    {
        Firebase.printf("Error task: %s, msg: %s, code: %d\n", aResult.uid().c_str(), aResult.error().message().c_str(), aResult.error().code());
    }

    if (aResult.available())
    {
        Firebase.printf("task: %s, payload: %s\n", aResult.uid().c_str(), aResult.c_str());
    }
}