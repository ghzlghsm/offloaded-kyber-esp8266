// mqtt_adapter.cpp
#include "mqtt_adapter.h"

void MqttAdapter::setWifiCred(const char* ssid, const char* pass) {
  _ssid = ssid;
  _pass = pass;
}
void MqttAdapter::_asm_reset_all() {
  for (uint8_t i=0;i<MQTT_ASM_SLOTS;i++) {
    _asm[i].active=false;
    _asm[i].total=0;
    _asm[i].topic[0]=0;
    _asm[i].last_ms=0;
    _asm[i].got_mask=0;
    _asm[i].exp_mask=0;
  }
}
void MqttAdapter::_asm_housekeep(uint32_t now) {
  for (uint8_t i=0;i<MQTT_ASM_SLOTS;i++) {
    if (!_asm[i].active) continue;
    if ((uint32_t)(now - _asm[i].last_ms) > (uint32_t)MQTT_ASM_TIMEOUT_MS) {
      _asm[i].active=false;
      _asm[i].got_mask=0;
      _asm[i].exp_mask=0;
      _asm[i].total=0;
      _asm[i].topic[0]=0;
      _asm[i].last_ms=0;
    }
  }
}

void MqttAdapter::begin(IPAddress host, uint16_t port, const char* clientId) {
  client.setServer(host, port);
  client.setClientId(clientId);
  client.setKeepAlive(120);

  _gotIp = WiFi.onStationModeGotIP([this](const WiFiEventStationModeGotIP&) {
    this->_connectMqtt();
  });

  _disconn = WiFi.onStationModeDisconnected([this](const WiFiEventStationModeDisconnected&) {
    this->connected = false;
    this->_inflight = 0; 
      if (this->_kyberBurstActive) {
        WiFi.setSleepMode(this->_kyberPrevSleep);
        this->_kyberBurstActive = false;
      }

    this->_asm_reset_all();
    this->_mqttReconnect.detach();
    this->_wifiReconnect.once(2, [this](){ this->_connectWifi(); });
  });


    client.onConnect([this](bool) {
    this->connected = true;
    if (this->onConnChange) this->onConnChange(true);
    this->_resubscribe_all();   // ✅ مهم: subscribe ها بعد از reconnect برمی‌گردند

  });


  client.onDisconnect([this](AsyncMqttClientDisconnectReason) {
    this->connected = false;
    if (this->onConnChange) this->onConnChange(false);
    this->_inflight = 0;
    this->_asm_reset_all();
    this->_mqttReconnect.once(2, [this](){ this->_connectMqtt(); });
  });

  client.onPublish([this](uint16_t) {
    MQTT_CRITICAL_START();
    if (this->_inflight) this->_inflight--;
    MQTT_CRITICAL_END();
  });

  client.onMessage([this](char* topic, char* payload, AsyncMqttClientMessageProperties,
                          size_t len, size_t index, size_t total) {
    this->onMessage(topic, payload, len, index, total);
  });

  _connectWifi();
}

void MqttAdapter::_connectWifi() {
  if (!_ssid || !_pass) return;
  WiFi.mode(WIFI_STA);
  WiFi.begin(_ssid, _pass);
}

void MqttAdapter::_connectMqtt() {
  client.connect();
}

void MqttAdapter::subscribe(const char* topic, uint8_t qos) {
  _remember_sub(topic, qos);     // cache
  if (connected) {
    client.subscribe(topic, qos);
  }
}
bool MqttAdapter::_rxq_push(const char* topic, const uint8_t* payload, uint16_t len) {
  uint8_t h = _rxh;
  uint8_t next = (uint8_t)((h + 1) % MQTT_RXQ_N);
  if (next == _rxt) return false;

  MqttRxItem& it = _rxq[h];
  strncpy(it.topic, topic, sizeof(it.topic) - 1);
  it.topic[sizeof(it.topic) - 1] = 0;

  if (len > sizeof(it.data)) len = sizeof(it.data);
  it.len = len;
  memcpy(it.data, payload, len);

  __sync_synchronize();
  _rxh = next;
  return true;
}

bool MqttAdapter::popRx(MqttRxItem& out) {
  _kyberNetRelax();

  uint8_t t = _rxt;
  uint8_t h = _rxh;
  if (t == h) return false;

  // ✅ این slot را producer دست نمی‌زند چون producer فقط روی _rxh می‌نویسد
  out = _rxq[t];

  __sync_synchronize();
  _rxt = (uint8_t)((t + 1) % MQTT_RXQ_N);
  return true;
}

void MqttAdapter::drainRxQueue() {
  MqttRxItem it;
  while (popRx(it)) {
    // drop
  }
}



MqttAdapter::RxAsm* MqttAdapter::_asm_find(const char* topic, uint16_t total) {
  for (uint8_t i=0;i<MQTT_ASM_SLOTS;i++) {
    if (!_asm[i].active) continue;
    if (_asm[i].total != total) continue;
    if (strncmp(_asm[i].topic, topic, sizeof(_asm[i].topic)) == 0) return &_asm[i];
  }
  return nullptr;
}

MqttAdapter::RxAsm* MqttAdapter::_asm_alloc(const char* topic, uint16_t total) {
  for (uint8_t i=0;i<MQTT_ASM_SLOTS;i++) {
    if (_asm[i].active) continue;

    _asm[i].active = true;
    _asm[i].total = total;
    strncpy(_asm[i].topic, topic, sizeof(_asm[i].topic)-1);
    _asm[i].topic[sizeof(_asm[i].topic)-1]=0;

    _asm[i].last_ms = millis();
    _asm[i].got_mask = 0;

    uint8_t blocks = (uint8_t)((total + 31u) / 32u);
    if (blocks == 0) blocks = 1;
    // blocks <= 32 (because MQTT_MAX_FRAME is limited). Use 32-bit masks.
    _asm[i].exp_mask = (blocks >= 32) ? 0xFFFFFFFFul : ((1ul << blocks) - 1ul);

    memset(_asm[i].buf, 0, sizeof(_asm[i].buf));

    return &_asm[i];
  }
  return nullptr;
}

static inline void mark_blocks(uint32_t& mask, uint16_t start, uint16_t end_exclusive) {
  uint16_t b0 = (uint16_t)(start / 32u);
  uint16_t b1 = (uint16_t)((end_exclusive - 1u) / 32u);
  for (uint16_t b=b0; b<=b1; b++) mask |= (1ul << b);
}

void MqttAdapter::onMessage(char* topic, char* payload, size_t len, size_t index, size_t total) {
  if (!topic || !payload) return;

  _kyberNetTouch(topic);
  if (total == 0) { _kyberNetRelax(); return; }
  if (total > MQTT_MAX_FRAME) { _kyberNetRelax(); return; }
  if (index + len > total) { _kyberNetRelax(); return; }

  // single piece
  if (index == 0 && len == total) {
    (void)_rxq_push(topic, (const uint8_t*)payload, (uint16_t)len);
    _kyberNetRelax();
    return;
  }

  // chunked
  RxAsm* a = _asm_find(topic, (uint16_t)total);
  if (!a) {
    if (index != 0){ _kyberNetRelax(); return; }
    a = _asm_alloc(topic, (uint16_t)total);
    if (!a) { _kyberNetRelax(); return; }
  }
  a->last_ms = millis();
  memcpy(a->buf + index, payload, len);
  mark_blocks(a->got_mask, (uint16_t)index, (uint16_t)(index + len));

  // فقط وقتی همه بلوک‌ها رسید push کن
  if (a->got_mask == a->exp_mask) {
    (void)_rxq_push(a->topic, a->buf, a->total);
    a->active = false;

  }
  _kyberNetRelax();
}

bool MqttAdapter::enqueue(const char* topic, const uint8_t* payload, uint16_t len, uint8_t qos, bool retain) {
  uint8_t h = _txh;
  uint8_t next = (uint8_t)((h + 1) % MQTT_TXQ_N);
  if (next == _txt) return false;

  MqttTxItem& it = _txq[h];
  strncpy(it.topic, topic, sizeof(it.topic) - 1);
  it.topic[sizeof(it.topic) - 1] = 0;

  if (len > sizeof(it.data)) len = sizeof(it.data);
  it.len = len;
  it.qos = qos;
  it.retain = retain ? 1 : 0;

  // ✅ کپی بیرون از noInterrupts
  memcpy(it.data, payload, len);

  __sync_synchronize();
  _txh = next;
  return true;
}


MqttTxItem* MqttAdapter::_txq_peek() {
  if (_txt == _txh) return nullptr;
  return &_txq[_txt];
}

void MqttAdapter::_txq_drop() {
  _txt = (uint8_t)((_txt + 1) % MQTT_TXQ_N);
}

void MqttAdapter::pumpTx() {
  if (!connected) return;
  _asm_housekeep(millis());

  uint8_t sent = 0;

  while (_inflight < MAX_INFLIGHT) {
    MqttTxItem* it = _txq_peek();
    if (!it) break;
    _kyberNetTouch(it->topic);
    uint16_t pid = client.publish(it->topic, it->qos, it->retain != 0,
                                  (const char*)it->data, it->len);
    if (pid == 0) {
      delay(0); 
      break;
    }
   // فقط اگر kyber/ بود، burst sleep رو موقتاً خاموش کن
    

    if (it->qos > 0) _inflight++;
    _txq_drop();

    // ✅ throttle + yield برای جلوگیری از WDT در QoS0 burst
    sent++;
    if (sent >= MQTT_PUMP_TX_BUDGET) break;
    if ((sent & 0x01) == 0) delay(0);  // هر 2 تا publish یک yield
  }
  _kyberNetRelax();
}


void MqttAdapter::_remember_sub(const char* topic, uint8_t qos) {
  if (!topic || !topic[0]) return;

  // اگر قبلاً بوده، فقط qos را آپدیت کن
  for (int i = 0; i < MQTT_SUBS_MAX; i++) {
    if (_subs[i].used && strncmp(_subs[i].topic, topic, MQTT_MAX_TOPIC) == 0) {
      _subs[i].qos = qos;
      return;
    }
  }

  // اولین اسلات خالی
  for (int i = 0; i < MQTT_SUBS_MAX; i++) {
    if (!_subs[i].used) {
      _subs[i].used = true;
      strncpy(_subs[i].topic, topic, MQTT_MAX_TOPIC - 1);
      _subs[i].topic[MQTT_MAX_TOPIC - 1] = 0;
      _subs[i].qos = qos;
      return;
    }
  }

  // اگر پر شد: عمداً هیچ کاری نمی‌کنیم (می‌تونی اینجا دیباگ/Serial بذاری)
}

void MqttAdapter::_resubscribe_all() {
  for (int i = 0; i < MQTT_SUBS_MAX; i++) {
    if (_subs[i].used) {
      client.subscribe(_subs[i].topic, _subs[i].qos);
      // (اختیاری) yield برای ESP8266
      delay(0);
    }
  }
}

