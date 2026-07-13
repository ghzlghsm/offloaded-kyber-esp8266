// helper1.ino (B) - single-frame protocol + cached seed
#include <Arduino.h>

#include "mqtt_adapter.h"

// small logging helper used in a few places
#ifndef LOGLN
#define LOGLN(x) Serial.println(x)
#endif
#include "protocol.h"
#include "mgmt_protocol.h"

extern "C" {
  #include "params.h"
  #include "poly.h"
  #include "polyvec.h"
  #include "indcpa.h"   // for gen_matrix
}

// -------------------- User config --------------------
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

IPAddress MQTT_HOST(192,168,1,102);
static const uint16_t MQTT_PORT = 1883;

static const char* HELPER_ID = "helper1";

// -------------------- QoS tuning --------------------
#ifndef KYBER_JOB_QOS
#define KYBER_JOB_QOS 0
#endif
#ifndef KYBER_CFG_QOS
#define KYBER_CFG_QOS 1
#endif

// -------------------- Kyber params --------------------
#define SP_PACKED_BYTES ((KYBER_K * KYBER_N * 3) / 8)  // 192 for K=2,N=256

// -------------------- Capabilities --------------------
static const uint8_t CAPS = MGMT_CAP_B;

// -------------------- MQTT + topics --------------------
static MqttAdapter g_mq;

static const char* t_status    = "status/helper1";
static char t_req[MQTT_MAX_TOPIC];
static char t_res[MQTT_MAX_TOPIC];
static char t_cfg_seed[MQTT_MAX_TOPIC];
static char t_cfg_ack[MQTT_MAX_TOPIC];

static char t_offer  [MQTT_MAX_TOPIC];
static char t_assign [MQTT_MAX_TOPIC];
static char t_mack   [MQTT_MAX_TOPIC];
static char t_release[MQTT_MAX_TOPIC];

// mgmt discovery
static char t_help[MQTT_MAX_TOPIC];

// -------------------- Lease state --------------------
static bool     g_leased = false;
static uint32_t g_lease_id = 0;
static uint32_t g_lease_deadline_ms = 0;
static uint32_t g_help_req_id = 0;
static uint8_t  g_help_need_caps = 0;
static uint32_t g_help_min_free = 0;
static uint16_t g_help_window = 0;
static uint16_t g_help_features = 0;
static uint8_t  g_help_repeat_left = 0;
static uint32_t g_help_next_ms = 0;
// -------------------- Cached seed + matrix --------------------
static bool     g_has_seed = false;
static uint32_t g_seed_key_id = 0;
static uint8_t  g_seed32[32];


// A^T rows (KYBER_K rows), generated from seed. In PQClean gen_matrix output is already NTT-domain.
static polyvec  g_at[KYBER_K];

// work buffers (avoid big stack)
static polyvec g_sp;
static polyvec g_b;
//static uint8_t g_out_b[KYBER_POLYVECBYTES];
static uint8_t g_out_b[KYBER_POLYVECBYTES + 4];

// scratch for frames
static uint8_t g_frame[MQTT_MAX_FRAME];

// last successful response cache (for QoS1 duplicates or re-sent requests)
static bool     g_last_res_valid = false;
static uint32_t g_last_job = 0;
static uint8_t  g_last_op  = 0;
static uint32_t g_last_key = 0;
static uint16_t g_last_frame_len = 0;
static uint8_t  g_last_frame[MQTT_MAX_FRAME];

// -------------------- Result pending (reliable TX) --------------------
static bool     g_busy_compute = false;        // true while computing b
static bool     g_res_pending  = false;        // result ready but not enqueued yet
static uint16_t g_res_pending_len = 0;
static uint8_t  g_res_pending_frame[MQTT_MAX_FRAME];
static uint32_t g_res_pending_job = 0;
static uint8_t  g_res_pending_op  = 0;
static uint32_t g_res_pending_key = 0;

// -------------------- Helpers --------------------
static inline void unpack_sp_raw(polyvec* sp, const uint8_t* in_packed) {
  uint32_t in_i = 0;

  for (int j = 0; j < KYBER_K; j++) {
    for (int i = 0; i < KYBER_N; i += 8) {
      uint32_t w = (uint32_t)in_packed[in_i + 0]
                 | ((uint32_t)in_packed[in_i + 1] << 8)
                 | ((uint32_t)in_packed[in_i + 2] << 16);
      in_i += 3;

      for (int k = 0; k < 8; k++) {
        uint32_t v = (w >> (3 * k)) & 0x7u;

        if (v > (uint32_t)(2 * KYBER_ETA1)) v = 0;
        sp->vec[j].coeffs[i + k] = (int16_t)((int)v - (int)KYBER_ETA1);
      }

      if ((i & 63) == 0) delay(0);
    }
    delay(0);
  }
}

static inline bool buildAndSend(uint8_t type, uint8_t op, uint32_t job_id, uint32_t key_id,
                                const uint8_t* payload, uint16_t plen)
{
  uint16_t flen = kproto_build(g_frame, (uint16_t)sizeof(g_frame),
                              type, op, 0, job_id, key_id, payload, plen);
  if (!flen) return false;
  return g_mq.enqueue(t_res, g_frame, flen, KYBER_JOB_QOS, false);
}

static inline void sendNack(uint32_t job_id, uint8_t op, uint32_t key_id, uint8_t code) {
  uint8_t p = code;
  (void)buildAndSend(KPROTO_T_NACK, op, job_id, key_id, &p, 1);
}

// compute b using cached matrix g_at and sp_raw
static bool compute_b_from_sp(const uint8_t* sp_raw, uint16_t sp_len, uint8_t* out, uint16_t* outlen) {
  if (!sp_raw || sp_len != (uint16_t)SP_PACKED_BYTES) return false;
  if (!g_has_seed) return false;

  unpack_sp_raw(&g_sp, sp_raw);
  delay(0);

  PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&g_sp);
  delay(0);

  for (int i=0; i<KYBER_K; i++) {
    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&g_b.vec[i], &g_at[i], &g_sp);
    delay(0);
  }

  PQCLEAN_MLKEM512_CLEAN_polyvec_invntt_tomont(&g_b);
  delay(0);

  PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(out, &g_b);
  *outlen = (uint16_t)KYBER_POLYVECBYTES;
  return true;
}

// -------------------- MGMT --------------------
static void sendAssignAck(uint32_t lease_id, uint8_t code) {
  uint8_t buf[MGMT_ASSIGN_ACK_LEN];
  mgmt_build_assign_ack(buf, lease_id, code);
  (void)g_mq.enqueue(t_mack, buf, MGMT_ASSIGN_ACK_LEN, MGMT_QOS_CTRL, false);
}

static inline uint8_t myStatus() {
  if (!g_mq.connected) return MGMT_STATUS_OFFLINE;
  if (!g_leased) {
  return (g_busy_compute || g_res_pending) ? MGMT_STATUS_BUSY : MGMT_STATUS_READY;
  }
  return (g_busy_compute || g_res_pending) ? MGMT_STATUS_BUSY : MGMT_STATUS_READY;
}

static void sendOffer(bool retained) {
  uint8_t buf[MGMT_OFFER_LEN];
  const uint32_t up = millis();
  const uint32_t freeh = ESP.getFreeHeap();
  const uint32_t maxb  = ESP.getMaxFreeBlockSize();
  const uint8_t frag   = (uint8_t)ESP.getHeapFragmentation();
  const uint8_t st     = myStatus();

  mgmt_build_offer(buf, up, freeh, maxb, frag, st, CAPS, g_lease_id);
  (void)g_mq.enqueue(t_offer, buf, MGMT_OFFER_LEN, MGMT_QOS_OFFER, retained);
}

static void sendOfferRsp(uint32_t req_id, uint8_t need_caps, uint32_t min_free, uint16_t window_ms, uint16_t features_mask) {
  (void)window_ms; (void)features_mask;

  // Only respond if we have required caps and enough memory.
  const uint32_t freeh = ESP.getFreeHeap();
  //if ((need_caps & CAPS) != need_caps) return;
  // پاسخ بده اگر حداقل یکی از capهای موردنیاز را داری
  if (need_caps != 0 && ((need_caps & CAPS) == 0)) return;
  if (freeh < min_free) return;

  uint8_t buf[MGMT_OFFER_RSP_LEN];
  const uint32_t up = millis();
  const uint32_t maxb  = ESP.getMaxFreeBlockSize();
  const uint8_t frag   = (uint8_t)ESP.getHeapFragmentation();
  const uint8_t st     = myStatus();

  mgmt_build_offer_rsp(buf, req_id, up, freeh, maxb, frag, st, CAPS, g_lease_id);
  (void)g_mq.enqueue(t_offer, buf, MGMT_OFFER_RSP_LEN, MGMT_QOS_OFFER_RSP, false);
}

// -------------------- RX dispatch --------------------
static void handleCfgSeed(const uint8_t* p, uint16_t len) {
  kproto_view_t v;
  if (!kproto_parse(p, len, &v)) return;
  if (v.type != KPROTO_T_CFG || v.op != KOP_SET_SEED) return;
  if (v.payload_len != 32) return;

  // If key is same and we already have it, ignore
  if (g_has_seed && g_seed_key_id == v.key_id) return;

  memcpy(g_seed32, v.payload, 32);
  delay(0);

  // compute matrix A^T once
  PQCLEAN_MLKEM512_CLEAN_gen_matrix(g_at, g_seed32, 1);
  delay(0);

  g_has_seed = true;
  g_seed_key_id = v.key_id;

  // CFG ack (non-retained): lets main know we are ready for RUN
  uint8_t ack[4] = {(uint8_t)(g_seed_key_id & 0xFF), (uint8_t)((g_seed_key_id >> 8) & 0xFF), (uint8_t)((g_seed_key_id >> 16) & 0xFF), (uint8_t)((g_seed_key_id >> 24) & 0xFF)};
  g_mq.enqueue(t_cfg_ack, (const uint8_t*)ack, 4, 1, false);
  // Invalidate last response cache (safe)
  g_last_res_valid = false;
}

static void handleReq(const uint8_t* p, uint16_t len) {
  kproto_view_t v;
  if (!kproto_parse(p, len, &v)) return;
  if (v.type != KPROTO_T_REQ) return;

  // Must be leased
  if (!g_leased) { sendNack(v.job_id, v.op, v.key_id, KERR_NOT_LEASED); return; }

  // Only op=B
  if (v.op != KOP_B) { sendNack(v.job_id, v.op, v.key_id, KERR_INTERNAL); return; }

  // Need seed (cached)
  if (!g_has_seed) { sendNack(v.job_id, v.op, v.key_id, KERR_NEED_SEED); return; }
  if (v.key_id != g_seed_key_id) { sendNack(v.job_id, v.op, v.key_id, KERR_KEY_MISMATCH); return; }

  // Dedup: if same job already answered successfully, resend it
  if (g_last_res_valid && v.job_id == g_last_job && v.op == g_last_op && v.key_id == g_last_key) {
    (void)g_mq.enqueue(t_res, g_last_frame, g_last_frame_len, KYBER_JOB_QOS, false);
    return;
  }

  if (v.payload_len != (uint16_t)SP_PACKED_BYTES) { sendNack(v.job_id, v.op, v.key_id, KERR_BAD_LEN); return; }
  /*g_busy_compute = true;
  uint16_t outlen = 0;
  if (!compute_b_from_sp(v.payload, v.payload_len, g_out_b, &outlen)) {
    g_busy_compute = false;
    sendNack(v.job_id, v.op, v.key_id, KERR_INTERNAL);
    return;
  }*/
  g_busy_compute = true;
  uint16_t outlen = 0;

  uint32_t comp_start_us = micros();
  bool comp_ok = compute_b_from_sp(v.payload, v.payload_len, g_out_b, &outlen);
  uint32_t comp_us = micros() - comp_start_us;

  if (!comp_ok) {
    g_busy_compute = false;
    sendNack(v.job_id, v.op, v.key_id, KERR_INTERNAL);
    return;
  }

  proto_wr_u32(g_out_b + outlen, comp_us);
  outlen += 4;
  // Build response into g_frame and send
  uint16_t flen = kproto_build(g_frame, (uint16_t)sizeof(g_frame),
                              KPROTO_T_RES, KOP_B, 0,
                              v.job_id, v.key_id,
                              g_out_b, outlen);
  if (!flen) { 
    g_busy_compute = false;
    sendNack(v.job_id, v.op, v.key_id, KERR_INTERNAL);
    return;
  }

  bool enq_ok = g_mq.enqueue(t_res, g_frame, flen, KYBER_JOB_QOS, false);
  g_busy_compute = false;

  if (enq_ok) {
    // cache last successful response frame
    if (flen <= (uint16_t)sizeof(g_last_frame)) {
      memcpy(g_last_frame, g_frame, flen);
      g_last_frame_len = flen;
      g_last_res_valid = true;
      g_last_job = v.job_id;
      g_last_op  = v.op;
      g_last_key = v.key_id;
    }
    return;
  }

  // enqueue fail => نگه‌داری pending برای retry
  if (flen <= (uint16_t)sizeof(g_res_pending_frame)) {
    memcpy(g_res_pending_frame, g_frame, flen);
    g_res_pending_len = flen;
    g_res_pending = true;
    g_res_pending_job = v.job_id;
    g_res_pending_op  = v.op;
    g_res_pending_key = v.key_id;
  } else {
    // اگر فریم جا نشد، حداقل cache قبلی invalid شود
    g_res_pending = false;
    g_res_pending_len = 0;
  }
}

static void handleMgmtAssign(const uint8_t* p, uint16_t len) {
  uint32_t lease_id=0, lease_ms=0, min_free=0; uint8_t role=0, req_caps=0;
  if (!mgmt_parse_assign(p, len, &lease_id, &role, &lease_ms, &min_free, &req_caps)) return;

  // Reject if caps mismatch
  if ((req_caps & CAPS) != req_caps) { sendAssignAck(lease_id, MGMT_ACK_BADCAPS); return; }

  // Reject if low memory
  if (ESP.getFreeHeap() < min_free) { sendAssignAck(lease_id, MGMT_ACK_LOWMEM); return; }

  // Accept
  g_leased = true;
  g_lease_id = lease_id;
  g_lease_deadline_ms = millis() + lease_ms;
  sendAssignAck(lease_id, MGMT_ACK_OK);

  // publish offer retained updated lease id
}

static void handleMgmtRelease(const uint8_t* p, uint16_t len) {
  uint32_t lease_id=0;
  if (!mgmt_parse_release(p, len, &lease_id)) return;
  if (!g_leased) return;
  if (lease_id != g_lease_id) return;

  g_leased = false;
  g_lease_id = 0;
  g_lease_deadline_ms = 0;
  resetJobStateOnLeaseEnd();

  // update offer
}

static void handleMgmtHelpWanted(const uint8_t* p, uint16_t len) {
  uint32_t req=0, min_free=0; uint16_t window=0, features=0; uint8_t need_caps=0;
  if (!mgmt_parse_help_wanted(p, len, &req, &need_caps, &min_free, &window, &features)) return;
  // اگر لیس شدیم، وارد discovery نشو (کم کردن spam و تداخل)
  if (g_leased) 
  {
    // یک پاسخ بدون repeat، با status BUSY/READY واقعی
    //sendOfferRsp(req, need_caps, min_free, window, features);
    return;
  }
  sendOfferRsp(req, need_caps, min_free, window, features);

  g_help_req_id = req;
  g_help_need_caps = need_caps;
  g_help_min_free = min_free;
  g_help_window = window;
  g_help_features = features;
  // we already sent 1 offer immediately; schedule 4 more (total 5)
  g_help_repeat_left = 4;
  g_help_next_ms = millis() + 100;
}
static void resetJobStateOnLeaseEnd() {
  g_busy_compute = false;
  g_res_pending = false;
  g_res_pending_len = 0;

  // cache پاسخ قبلی هم بهتره پاک شود تا با lease جدید قاطی نشود
  g_last_res_valid = false;
}
static void tickLease() {
  if (g_leased && g_lease_deadline_ms && (int32_t)(millis() - g_lease_deadline_ms) > 0) {
    g_leased = false;
    g_lease_id = 0;
    g_lease_deadline_ms = 0;
    resetJobStateOnLeaseEnd();
}
}

/*static void tickOffer() {
  static uint32_t last_ms = 0;
  const uint32_t now = millis();
  if ((uint32_t)(now - last_ms) < 1000) return;
  last_ms = now;
}*/

static void tickHelpRepeats() {
  if (!g_help_repeat_left) return;
  if (!g_mq.connected) return;
  uint32_t now = millis();
  if ((int32_t)(now - g_help_next_ms) < 0) return;

  // Non-retained burst (5x, 100ms) to survive loss
  sendOfferRsp(g_help_req_id, g_help_need_caps, g_help_min_free, g_help_window, g_help_features);

  g_help_repeat_left--;
  g_help_next_ms = now + 100;
}


static void tickResultTx() {
  if (!g_res_pending) return;
  if (!g_mq.connected) return;

  // اگر لیس نداری، نتیجه قدیمی رو نگه ندار (این سیاست رو می‌تونی عوض کنی)
  if (!g_leased) {
    g_res_pending = false;
    g_res_pending_len = 0;
    return;
  }

  if (g_res_pending_len == 0 || g_res_pending_len > (uint16_t)sizeof(g_res_pending_frame)) {
    g_res_pending = false;
    g_res_pending_len = 0;
    return;
  }

  // تلاش برای enqueue دوباره
  if (g_mq.enqueue(t_res, g_res_pending_frame, g_res_pending_len, KYBER_JOB_QOS, false)) {
    // موفق شد => pending پاک شود و cache "آخرین پاسخ موفق" هم آپدیت شود
    if (g_res_pending_len <= (uint16_t)sizeof(g_last_frame)) {
      memcpy(g_last_frame, g_res_pending_frame, g_res_pending_len);
      g_last_frame_len = g_res_pending_len;
      g_last_res_valid = true;
      g_last_job = g_res_pending_job;
      g_last_op  = g_res_pending_op;
      g_last_key = g_res_pending_key;
    }

    g_res_pending = false;
    g_res_pending_len = 0;
  }
}
// -------------------- Setup/loop --------------------
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.printf("\nBOOT(%s)\n", HELPER_ID);
  Serial.printf("free heap=%u\n", ESP.getFreeHeap());

  snprintf(t_req, sizeof(t_req), "kyber/%s/req", HELPER_ID);
  snprintf(t_res, sizeof(t_res), "kyber/%s/res", HELPER_ID);
  snprintf(t_cfg_seed, sizeof(t_cfg_seed), "kyber/%s/cfg/seed", HELPER_ID);
  snprintf(t_cfg_ack, sizeof(t_cfg_ack), "kyber/%s/cfg/ack", HELPER_ID);

  snprintf(t_offer,    sizeof(t_offer),    "mgmt/offer/%s",   HELPER_ID);
  snprintf(t_assign,   sizeof(t_assign),   "mgmt/assign/%s",  HELPER_ID);
  snprintf(t_mack,     sizeof(t_mack),     "mgmt/ack/%s",     HELPER_ID);
  snprintf(t_release,  sizeof(t_release),  "mgmt/release/%s", HELPER_ID);
  snprintf(t_help,     sizeof(t_help),     "%s", MGMT_HELP_TOPIC);

  static char clientId[32];
  snprintf(clientId, sizeof(clientId), "ESP_%s", HELPER_ID);

  g_mq.setWifiCred(WIFI_SSID, WIFI_PASS);

  // LWT: presence (retained) for main to detect lost/reconnect
  g_mq.client.setWill(t_status, 1, true, "offline");
  g_mq.begin(MQTT_HOST, MQTT_PORT, clientId);

  g_mq.kyberBurstEnable(true);
  g_mq.kyberBurstSetHoldMs(220);

  g_mq.onConnChange = [](bool up){
    LOGLN(up ? "[MQTT] connected" : "[MQTT] disconnected");
    if (up) {
      // Presence beacon (retained) for lost/reconnect detection
      static const char kOnline[] = "online";
      g_mq.enqueue(t_status, (const uint8_t*)kOnline, 6, 1, true);
    }
  };

  // subscriptions
  g_mq.subscribe(t_req,      1);
  g_mq.subscribe(t_cfg_seed, 1);

  g_mq.subscribe(t_assign, 1);
  g_mq.subscribe(t_release, 1);
  g_mq.subscribe(t_help, 1);

  WiFi.setSleepMode(WIFI_NONE_SLEEP);
}

void loop() {
  g_mq.pumpTx();
  tickResultTx();

  tickLease();
  tickHelpRepeats();
  // RX
  MqttRxItem it;
  for (uint8_t k=0; k<24; k++) {
    if (!g_mq.popRx(it)) break;

    if (strcmp(it.topic, t_cfg_seed) == 0) {
      handleCfgSeed(it.data, it.len);
    } else if (strcmp(it.topic, t_req) == 0) {
      handleReq(it.data, it.len);
    } else if (strcmp(it.topic, t_assign) == 0) {
      handleMgmtAssign(it.data, it.len);
    } else if (strcmp(it.topic, t_release) == 0) {
      handleMgmtRelease(it.data, it.len);
    } else if (strcmp(it.topic, t_help) == 0) {
      handleMgmtHelpWanted(it.data, it.len);
    }

    if ((k & 0x07) == 0x07) delay(0);
  }

  delay(0);
}
