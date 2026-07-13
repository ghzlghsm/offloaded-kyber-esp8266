#pragma once
#include <Arduino.h>
#include <string.h>
#include "mqtt_adapter.h"
#include "mgmt_protocol.h"

#ifndef MGMT_HELP_TOPIC
#define MGMT_HELP_TOPIC "mgmt/help"
#endif

// During discovery, main repeats HELP_WANTED to reduce chance of helpers missing it (late join, WiFi jitter).
#ifndef MGMT_HELP_REPEAT_MS
#define MGMT_HELP_REPEAT_MS 5000
#endif



#ifndef MGMT_MAX_HELPERS
#define MGMT_MAX_HELPERS 8
#endif

struct MgmtHelperRec {
  bool used = false;
  char id[16] = {0};

  uint32_t last_seen_ms = 0;

  uint32_t free_heap = 0;
  uint32_t max_block = 0;
  uint8_t  frag_pct  = 0;
  uint8_t  status    = MGMT_STATUS_OFFLINE;
  uint8_t  caps      = 0;
  uint32_t lease_id  = 0;
};

class MgmtManager {
public:
  void begin(MqttAdapter* mq) { _mq = mq; }

  uint32_t startDiscovery(uint8_t need_caps, uint32_t min_free_heap, uint16_t window_ms, uint16_t features_mask=0) {
    _clear();
    _need_caps = need_caps;
    _min_free  = min_free_heap;
    _window_ms = window_ms;
    _features_mask = features_mask;
    _req_id = ((uint32_t)millis() << 16) ^ (uint32_t)random(1, 0x7fffffff);
    _deadline_ms = millis() + window_ms;
    _active = true;

    uint8_t buf[MGMT_HELP_WANTED_LEN];
    mgmt_build_help_wanted(buf, _req_id, need_caps, min_free_heap, window_ms, features_mask);
    if (_mq) (void)_mq->enqueue(MGMT_HELP_TOPIC, buf, MGMT_HELP_WANTED_LEN, MGMT_QOS_CTRL, false);
    _last_help_send_ms = millis();
    return _req_id;
  }

  

// Call frequently (e.g., every loop) while discovery is active.
// Re-sends HELP_WANTED periodically until the discovery window expires.
void tick() {
  if (!_active) return;
  uint32_t now = millis();
  //if ((int32_t)(now - _deadline_ms) > 0) return;
  if ((int32_t)(now - _deadline_ms) > 0) {  return; }
 
  if (_last_help_send_ms != 0 &&(uint32_t)(now - _last_help_send_ms) < MGMT_HELP_REPEAT_MS) return;
  
  _last_help_send_ms = now;
  uint8_t buf[MGMT_HELP_WANTED_LEN];
  mgmt_build_help_wanted(buf, _req_id, _need_caps, _min_free, _window_ms, _features_mask);
  if (_mq) (void)_mq->enqueue(MGMT_HELP_TOPIC, buf, MGMT_HELP_WANTED_LEN, MGMT_QOS_CTRL, false);
}
bool active() const { return _active; }
void endDiscovery() { _active = false; }
  bool expired() const { return _active && (int32_t)(millis() - _deadline_ms) > 0; }
  uint32_t reqId() const { return _req_id; }

  void onOffer(const char* helper_id, const uint8_t* p, uint16_t len) {
    if (!_active) return;

    uint32_t req=0, up=0, freeh=0, maxb=0, lease=0;
    uint8_t frag=0, st=0, caps=0;

    if (len == MGMT_OFFER_RSP_LEN && p[0] == MGMT_VER && p[1] == MGMT_OFFER_RSP) {
      if (!mgmt_parse_offer_rsp(p, len, &req, &up, &freeh, &maxb, &frag, &st, &caps, &lease)) return;
      if (req != _req_id) return;
    } else if (len == MGMT_OFFER_LEN && p[0] == MGMT_VER && p[1] == MGMT_OFFER) {
      // fallback legacy
      //return;
      if (!mgmt_parse_offer(p, len, &up, &freeh, &maxb, &frag, &st, &caps, &lease)) return;
    } else {
      return;
    }

    MgmtHelperRec* r = _findOrAlloc(helper_id);
    if (!r) return;

    r->last_seen_ms = millis();
    r->free_heap = freeh;
    r->max_block = maxb;
    r->frag_pct  = frag;
    r->status    = st;
    r->caps      = caps;
    r->lease_id  = lease;
  }

  bool pickTwo(char* out_b, size_t nb, char* out_v, size_t nv,
               uint8_t cap_b = MGMT_CAP_B, uint8_t cap_v = MGMT_CAP_V) const
  {
    int ib = _bestIndex(cap_b, -1);
    if (ib < 0) return false;
    int iv = _bestIndex(cap_v, ib);
    if (iv < 0) return false;

    strncpy(out_b, _h[ib].id, nb); out_b[nb-1]=0;
    strncpy(out_v, _h[iv].id, nv); out_v[nv-1]=0;
    return true;
  }

private:
  MqttAdapter* _mq = nullptr;
  MgmtHelperRec _h[MGMT_MAX_HELPERS];

  bool _active = false;
  uint32_t _req_id = 0;
  uint32_t _deadline_ms = 0;

  uint8_t  _need_caps = 0;
  uint32_t _min_free  = 0;
  uint16_t _window_ms = 0;

  

uint32_t _last_help_send_ms = 0;
uint16_t _features_mask = 0;
void _clear() {
    for (uint8_t i=0;i<MGMT_MAX_HELPERS;i++) _h[i].used=false;
  }

  MgmtHelperRec* _findOrAlloc(const char* id) {
    for (uint8_t i=0;i<MGMT_MAX_HELPERS;i++) {
      if (_h[i].used && strcmp(_h[i].id, id)==0) return &_h[i];
    }
    for (uint8_t i=0;i<MGMT_MAX_HELPERS;i++) {
      if (!_h[i].used) {
        _h[i].used=true;
        strncpy(_h[i].id, id, sizeof(_h[i].id));
        _h[i].id[sizeof(_h[i].id)-1]=0;
        return &_h[i];
      }
    }
    return nullptr;
  }

  static int64_t _score(const MgmtHelperRec& r) {
    // اولویت: free_heap بالا، بعد max_block بالا، frag پایین
    int64_t s = 0;
    s += (int64_t)r.free_heap;
    s += (int64_t)r.max_block / 2;
    s -= (int64_t)r.frag_pct * 50;
    return s;
  }

  int _bestIndex(uint8_t need_cap, int exclude) const {
    int best=-1;
    int64_t bestS = -(1LL<<60);

    for (uint8_t i=0;i<MGMT_MAX_HELPERS;i++) {
      if (!_h[i].used) continue;
      if ((int)i == exclude) continue;

      const MgmtHelperRec& r = _h[i];

      // باید READY باشه و cap لازم رو داشته باشه
      if (r.status != MGMT_STATUS_READY) continue;
      if ((r.caps & need_cap) != need_cap) continue;
      if (r.free_heap < _min_free) continue;

      int64_t s = _score(r);
      if (s > bestS) { bestS=s; best=(int)i; }
    }
    return best;
  }
};
