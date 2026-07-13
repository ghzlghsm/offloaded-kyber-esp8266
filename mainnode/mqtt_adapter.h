// mqtt_adapter.h
#pragma once
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <AsyncMqttClient.h>
#include <Ticker.h>
#include <stdint.h>
#include <string.h>

#ifndef MQTT_MAX_TOPIC
#define MQTT_MAX_TOPIC 32
#endif

#ifndef MQTT_MAX_FRAME
#define MQTT_MAX_FRAME 832
#endif

// RX queue capacity
#ifndef MQTT_RXQ_N
#define MQTT_RXQ_N 12
#endif

// TX queue capacity
#ifndef MQTT_TXQ_N
#define MQTT_TXQ_N 8
#endif

// assembler slots for chunked MQTT callback
#ifndef MQTT_ASM_SLOTS
#define MQTT_ASM_SLOTS 2
#endif

#ifndef MQTT_SUBS_MAX
#define MQTT_SUBS_MAX 12
#endif

#ifndef MQTT_ASM_TIMEOUT_MS
#define MQTT_ASM_TIMEOUT_MS 1500
#endif

#ifndef MQTT_CRITICAL_START
#define MQTT_CRITICAL_START() noInterrupts()
#endif
#ifndef MQTT_CRITICAL_END
#define MQTT_CRITICAL_END() interrupts()
#endif

#ifndef MQTT_PUMP_TX_BUDGET
#define MQTT_PUMP_TX_BUDGET 8   // در هر pumpTx حداکثر 4 publish
#endif

struct MqttRxItem {
  char     topic[MQTT_MAX_TOPIC];
  uint16_t len;
  uint8_t  data[MQTT_MAX_FRAME];
};

struct MqttTxItem {
  char     topic[MQTT_MAX_TOPIC];
  uint16_t len;
  uint8_t  qos;
  uint8_t  retain;
  uint8_t  data[MQTT_MAX_FRAME];
};

class MqttAdapter {
public:
  AsyncMqttClient client;

  // public flags
  volatile bool connected = false;
  
  // optional hooks
  void (*onConnChange)(bool up) = nullptr;

  // init
  void begin(IPAddress host, uint16_t port, const char* clientId);
  void setWifiCred(const char* ssid, const char* pass);

  // subscribe helper
  void subscribe(const char* topic, uint8_t qos);

  // enqueue publish (copied into TX queue)
  bool enqueue(const char* topic, const uint8_t* payload, uint16_t len, uint8_t qos, bool retain=false);

  // pump TX (call in loop)
  void pumpTx();

  // pop RX items (call in loop)
  bool popRx(MqttRxItem& out);

  // Drop all pending RX items (use before starting benchmark)
  void drainRxQueue();

  // must be called from callbacks
  void onMessage(char* topic, char* payload, size_t len, size_t index, size_t total);

  // yields for ESP8266
  static uint32_t nowMs(void* u) { (void)u; return millis(); }
  static void yieldFn(void* u) { (void)u; delay(0); }

  // ---- Kyber-only adaptive WiFi sleep (battery-friendly) ----
  void kyberBurstEnable(bool en) { _kyberBurstEnabled = en; }
  void kyberBurstSetHoldMs(uint32_t ms) { _kyberBurstHoldMs = ms; }


private:
  // wifi
  const char* _ssid=nullptr;
  const char* _pass=nullptr;

  // ---- Kyber-only burst sleep control ----
  bool _kyberBurstEnabled = false;
  bool _kyberBurstActive = false;
  WiFiSleepType_t _kyberPrevSleep = WIFI_LIGHT_SLEEP;
  uint32_t _kyberLastMs = 0;
  uint32_t _kyberBurstHoldMs = 180; // 100..300ms پیشنهادی

  static inline bool _isKyberTopic(const char* t) {
    return t && (strncmp(t, "kyber/", 6) == 0);
  }

  inline void _kyberNetTouch(const char* topic) {
    if (!_kyberBurstEnabled) return;
    if (!_isKyberTopic(topic)) return;

    _kyberLastMs = millis();
    if (!_kyberBurstActive) {
      _kyberPrevSleep = WiFi.getSleepMode();   // هرچی قبلاً بوده (LIGHT/MODEM/...)
      WiFi.setSleepMode(WIFI_NONE_SLEEP);      // فقط هنگام kyber burst
      _kyberBurstActive = true;
    }
  }

  inline void _kyberNetRelax() {
    if (!_kyberBurstEnabled) return;
    if (_kyberBurstActive &&
        (uint32_t)(millis() - _kyberLastMs) > _kyberBurstHoldMs) {
      WiFi.setSleepMode(_kyberPrevSleep);      // برگرد به حالت قبلی
      _kyberBurstActive = false;
    }
  }


  WiFiEventHandler _gotIp;
  WiFiEventHandler _disconn;
  Ticker _wifiReconnect;
  Ticker _mqttReconnect;

  // RXQ
  volatile uint8_t _rxh=0, _rxt=0;
  MqttRxItem _rxq[MQTT_RXQ_N];

  // TXQ
  volatile uint8_t _txh=0, _txt=0;
  MqttTxItem _txq[MQTT_TXQ_N];
  volatile uint8_t _inflight=0;
  static const uint8_t MAX_INFLIGHT = 4;

    // subscriptions cache (for re-subscribe after reconnect)
  struct SubRec {
    bool used = false;
    char topic[MQTT_MAX_TOPIC];
    uint8_t qos = 0;
  } _subs[MQTT_SUBS_MAX];

  void _resubscribe_all();
  void _remember_sub(const char* topic, uint8_t qos);


  // assembler
  struct RxAsm {
    bool active=false;
    char topic[MQTT_MAX_TOPIC];
    uint16_t total=0;
    uint8_t buf[MQTT_MAX_FRAME];
    uint32_t last_ms=0;
    // bitmap برای اینکه بفهمیم همه بخش‌ها رسیدند یا نه (هر 32 بایت یک بیت)
    uint32_t got_mask=0;
    uint32_t exp_mask=0;
    } _asm[MQTT_ASM_SLOTS];

  // internal helpers
  void _connectWifi();
  void _connectMqtt();
  void _asm_housekeep(uint32_t now);
  void _asm_reset_all();

  bool _rxq_push(const char* topic, const uint8_t* payload, uint16_t len);
  RxAsm* _asm_find(const char* topic, uint16_t total);
  RxAsm* _asm_alloc(const char* topic, uint16_t total);
  MqttTxItem* _txq_peek();
  void _txq_drop();
};
