struct HelperLink;
// mainnode.ino (Kyber offload main) - single-frame protocol + cached seed/t
#include <Arduino.h>
#define CFG_RETRY_MS 2000
#include <math.h>
#include <LittleFS.h>

static const uint32_t CFG_SETTLE_MS = 200; // wait after cfg before RUN
#include "mqtt_adapter.h"
#include "protocol.h"
#include "mgmt_protocol.h"
#include "mgmt_manager.h"
#include <ESP8266WiFi.h>
#include "coop.h"

// ===== PQClean ML-KEM-512 (Kyber) =====
extern "C" {
  #include "api.h"
  #include "params.h"
}
#include "kyber_offload_api.h"

// -------------------- Logging --------------------
#ifndef LOG_ENABLE
#define LOG_ENABLE 1
#endif

#ifndef BENCH_VERBOSE
#define BENCH_VERBOSE 1
#endif

#if BENCH_VERBOSE
  #define LOGI(...)  do{ Serial.printf(__VA_ARGS__); }while(0)
  #define LOGLN(...) do{ Serial.printf(__VA_ARGS__); Serial.println(); }while(0)
#else
  #define LOGI(...)  do{}while(0)
  #define LOGLN(...) do{}while(0)
#endif

// -------------------- User config --------------------
static const char* WIFI_SSID = "YOUR_WIFI_NAME";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

IPAddress MQTT_HOST(192,168,1,102);
static const uint16_t MQTT_PORT = 1883;

static const char* MAIN_ID = "main";
static const char* H1_ID   = "helper1";
static const char* H2_ID   = "helper2";

// -------------------- Kyber params --------------------
#define SP_PACKED_BYTES ((KYBER_K * KYBER_N * 3) / 8)  // for K=2,N=256 => 192

// -------------------- QoS tuning --------------------
// For lowest latency on a stable LAN, QoS0 is fastest.
// If you prefer more reliability, change to 1 (and helpers will still be safe).
#ifndef KYBER_JOB_QOS
#define KYBER_JOB_QOS 0
#endif

#ifndef KYBER_CFG_QOS
#define KYBER_CFG_QOS 1
#endif

#ifndef KYBER_JOB_TIMEOUT_MS
#define KYBER_JOB_TIMEOUT_MS 1200
#endif

// -------------------- Globals --------------------
static MqttAdapter g_mq;
static volatile bool g_kyber_busy = false;
// Discovery/selection (collect offers in a short window, then assign)
static MgmtManager g_mgmt;
extern "C" { volatile uint8_t g_load = 0; }


// -------------------- Main phase (BOOT/RUN) --------------------
enum MainPhase {
  PHASE_BOOT,   // discovery/assign/cfg only
  PHASE_RUN     // kyber benchmark + coop load
};

static MainPhase g_phase = PHASE_BOOT;
static bool     g_cfgSent   = false;   // both cfg (seed/t) published for current key_id
static volatile bool g_h1_online = false;
static volatile bool g_h2_online = false;
static volatile bool g_abort_iteration = false; // set when any helper goes offline (status/LWT)
static volatile bool g_defer_boot = false;      // request BOOT after safe-point

static bool     g_rxDrained = false;   // RX queue drained after cfg
static uint32_t g_cfgSentAt = 0;       // ms timestamp of cfg completion

static volatile bool g_bench_reset = false; // request to reset benchmark state (on re-bootstrap)
//......................
struct EncTrace {
  uint32_t job_id;

  uint32_t t_req_enq_us;     // زمان enqueue
  uint32_t t_req_sent_us;    // زمان publish واقعی
  uint32_t t_res_rx_us;      // زمان رسیدن res
  uint32_t t_res_done_us;    // زمان پایان پردازش res

  uint32_t qdelay_us;
  uint32_t net_helper_us;
  uint32_t rxcopy_us;

  bool h1_done;
  bool h2_done;
};

static EncTrace g_trace;
//.............................

// key storage
static uint8_t g_pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
static uint8_t g_sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
static bool g_has_keys = false;

// cached parts derived from public key
static uint8_t  g_seed32[32];
static uint8_t  g_t_bytes[KYBER_POLYVECBYTES]; // pkpv/t = 768
static uint32_t g_key_id = 0;                 // cache/version tag for helpers

// helper results (no big stack)
static uint8_t g_b_bytes[KYBER_POLYVECBYTES];
static uint8_t g_v_bytes[KYBER_POLYBYTES];

// scratch frame buffers (single global, used only from loop context)
static uint8_t g_frame_buf[MQTT_MAX_FRAME];

// -------------------- Topics helpers --------------------
static void makeKyber(char* out, size_t n, const char* id, const char* tail) {
  // "kyber/<id>/<tail>"
  snprintf(out, n, "kyber/%s/%s", id, tail);
}
static void makeMgmt(char* out, size_t n, const char* kind, const char* id) {
  snprintf(out, n, "mgmt/%s/%s", kind, id);
}
// ===================== Coop IoT load on MAIN node =====================
// load percent: 0..90
// CRC32 step (small + real)
static inline uint32_t crc32_update(uint32_t crc, uint8_t data) {
  crc ^= data;
  for (int i = 0; i < 8; i++) {
    uint32_t mask = -(int32_t)(crc & 1u);
    crc = (crc >> 1) ^ (0xEDB88320u & mask);
  }
  return crc;
}

static uint32_t iot_lfsr = 0xACE1u;
static int32_t  iot_filtY_q15 = 0;
static const int32_t iot_alpha_q15 = 1638; // ~0.05
static uint32_t iot_crc = 0xFFFFFFFFu;
static uint8_t  iot_buf[128];

// یک slice کوتاه از کار IoT، متناسب با g_load
static inline void iot_load_slice() {
  uint8_t p = g_load;
  if (p == 0) return;

  const uint32_t WINDOW_US = 2000;               // پنجره 2ms
  uint32_t budget_us = (WINDOW_US * (uint32_t)p) / 100;
  if (budget_us == 0) return;

  uint32_t t0 = micros();
  while ((uint32_t)(micros() - t0) < budget_us) {
    // 1) fake sensor (LFSR)
    iot_lfsr = (iot_lfsr >> 1) ^ (-(int32_t)(iot_lfsr & 1u) & 0xB400u);
    int16_t noise = (int16_t)(iot_lfsr & 0x3F) - 32;

    static int16_t ramp = -1000;
    ramp += 25;
    if (ramp > 1000) ramp = -1000;
    int16_t x = ramp + noise;

    // 2) IIR filter (Q15)
    int32_t x_q15 = ((int32_t)x) << 15;
    int32_t err   = x_q15 - iot_filtY_q15;
    iot_filtY_q15 = iot_filtY_q15 + ((err * iot_alpha_q15) >> 15);
    int16_t y = (int16_t)(iot_filtY_q15 >> 15);

    // 3) pack into buffer
    uint32_t t = micros();
    iot_buf[0] = (uint8_t)(y & 0xFF);
    iot_buf[1] = (uint8_t)((y >> 8) & 0xFF);
    iot_buf[2] = (uint8_t)(t & 0xFF);
    iot_buf[3] = (uint8_t)((t >> 8) & 0xFF);

    // 4) CRC
    iot_crc = crc32_update(iot_crc, iot_buf[0]);
    iot_crc = crc32_update(iot_crc, iot_buf[1]);
    iot_crc = crc32_update(iot_crc, iot_buf[2]);
    iot_crc = crc32_update(iot_crc, iot_buf[3]);

    // 5) memory traffic
    for (int i = 4; i < 64; i++) {
      iot_buf[i] ^= (uint8_t)(iot_crc >> (i & 7));
    }
  }

  // cooperate with WiFi/WDT
  delay(0);
}
// -------------------- Helper link --------------------
struct HelperLink {
  char id[16] = {0};   // به‌جای pointer، خود رشته ذخیره می‌شود

  // kyber data-plane
  char t_req[MQTT_MAX_TOPIC];
  char t_res[MQTT_MAX_TOPIC];
  char t_cfg[MQTT_MAX_TOPIC];   // cfg/seed or cfg/t

  // mgmt control-plane
  char t_assign[MQTT_MAX_TOPIC];
  char t_ack[MQTT_MAX_TOPIC];
  char t_release[MQTT_MAX_TOPIC];

  uint8_t required_caps = 0;
  uint8_t role = 0;

  // lease
  bool     leased = false;
  uint32_t lease_id = 0;
  uint32_t lease_deadline_ms = 0;
  bool     assign_pending = false;
  uint32_t assign_last_send_ms = 0;
  uint8_t  assign_retries = 0;

  // cfg publish tracking
  bool     cfg_sent = false;
  uint32_t cfg_key_id_sent = 0;

  uint32_t cfg_sent_at = 0; // millis() when cfg was last published (non-retained)
  bool cfg_acked = false;
  bool online = false;
  char t_cfg_ack[32] = {0};
  // last request (for resend on NACK)
  uint32_t last_req_job = 0;
  uint8_t  last_req_op  = 0;
  uint32_t last_req_key = 0;
  uint8_t  last_req_payload[SP_PACKED_BYTES];
  bool     last_req_valid = false;

  // response tracking
  volatile bool res_ready = false;
  uint16_t res_len = 0;
  uint8_t* res_buf = nullptr;
  uint16_t res_cap = 0;

  // profiling
  uint32_t t_start_us = 0;
  uint32_t t_req_sent_us = 0;
  uint32_t t_res_first_us = 0;
  uint32_t t_res_done_us = 0;
  uint32_t helper_comp_us = 0;
  uint32_t rtt_us = 0;
  uint32_t comm_oh_us = 0;

  // retry throttle
  uint32_t last_retry_ms = 0;
};

static HelperLink H1, H2;

// -------------------- Utility --------------------
static inline uint32_t nowMs(){ return millis(); }
static uint32_t g_last_job_id = 0;
static uint32_t allocJobId() {
  uint32_t id = nowMs();
  if (id == g_last_job_id) id++;
  g_last_job_id = id;
  return id;
}

// -------------------- Keys --------------------
static bool loadKeysOrMake() {
  if (!LittleFS.begin()) return false;

  const char* PK_PATH="/kyber_pk.bin";
  const char* SK_PATH="/kyber_sk.bin";

  File fpk, fsk;

  auto cleanup = [&](){
    if (fpk) fpk.close();
    if (fsk) fsk.close();
    LittleFS.end();
  };

  // try load
  if (LittleFS.exists(PK_PATH) && LittleFS.exists(SK_PATH)) {
    fpk = LittleFS.open(PK_PATH,"r");
    fsk = LittleFS.open(SK_PATH,"r");
    if (!fpk || !fsk) { cleanup(); return false; }

    if (fpk.read(g_pk, sizeof(g_pk)) != (int)sizeof(g_pk)) { cleanup(); return false; }
    if (fsk.read(g_sk, sizeof(g_sk)) != (int)sizeof(g_sk)) { cleanup(); return false; }

    cleanup();
    return true;
  }

  // generate
  uint32_t t0 = micros();
  int rc = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(g_pk, g_sk);
  uint32_t dt = micros() - t0;
  Serial.printf("KEYGEN: rc=%d time_us=%lu\n", rc, (unsigned long)dt);
  if (rc != 0) { cleanup(); return false; }

  fpk = LittleFS.open(PK_PATH,"w");
  fsk = LittleFS.open(SK_PATH,"w");
  if (!fpk || !fsk) { cleanup(); return false; }

  fpk.write(g_pk, sizeof(g_pk));
  fsk.write(g_sk, sizeof(g_sk));

  cleanup();
  return true;
}

static void deriveKeyParts() {
  // ML-KEM-512 public key bytes layout: t(768) || seed(32)
  memcpy(g_t_bytes, g_pk, KYBER_POLYVECBYTES);
  memcpy(g_seed32, g_pk + KYBER_POLYVECBYTES, 32);

  // KeyId is only for cache versioning (not crypto)
  g_key_id = proto_fnv1a32(g_pk, (uint32_t)sizeof(g_pk));
}

// -------------------- Lease (simple, fixed helpers) --------------------
static void initHelper(HelperLink& h, const char* id, uint8_t caps, uint8_t role,
                       const char* cfg_tail, uint8_t* res_buf, uint16_t res_cap)
{
  h.required_caps = caps;
  h.role = role;
  h.res_buf = res_buf;
  h.res_cap = res_cap;

  // کپی امن id داخل HelperLink (به‌جای نگه‌داشتن pointer)
  strncpy(h.id, id ? id : "", sizeof(h.id));
  h.id[sizeof(h.id) - 1] = 0;

  // از این به بعد همه topic ها را با h.id بساز
  makeKyber(h.t_req, sizeof(h.t_req), h.id, "req");
  makeKyber(h.t_res, sizeof(h.t_res), h.id, "res");
  makeKyber(h.t_cfg, sizeof(h.t_cfg), h.id, cfg_tail);

  makeMgmt(h.t_assign,  sizeof(h.t_assign),  "assign",  h.id);
  makeMgmt(h.t_ack,     sizeof(h.t_ack),     "ack",     h.id);
  makeMgmt(h.t_release, sizeof(h.t_release), "release", h.id);

  h.leased = false;
  h.lease_id = 0;
  h.lease_deadline_ms = 0;
  h.assign_pending = false;
  h.assign_last_send_ms = 0;
  h.assign_retries = 0;
  h.cfg_sent = false;
  h.cfg_key_id_sent = 0;
  h.last_req_valid = false;
  h.res_ready = false;
  h.res_len = 0;
  h.t_start_us = h.t_req_sent_us = h.t_res_first_us = h.t_res_done_us = 0;
  h.helper_comp_us = 0;
  h.rtt_us = 0;
  h.comm_oh_us = 0;
  h.last_retry_ms = 0;
}

static void sendAssign(HelperLink& h) {
  // config
  const uint32_t LEASE_MS = 600000;
  const uint32_t MIN_FREE = 7000;  // adjust if needed

  // new lease_id per (re)assign
  if (h.lease_id == 0) {
    h.lease_id = ((uint32_t)micros() << 8) ^ (uint32_t)random(1, 0x7fffffff);
  }

  uint8_t buf[MGMT_ASSIGN_LEN];
  mgmt_build_assign(buf, h.lease_id, h.role, LEASE_MS, MIN_FREE, h.required_caps);
  
  (void)g_mq.enqueue(h.t_assign, buf, MGMT_ASSIGN_LEN, MGMT_QOS_CTRL, false);
  LOGLN("[ASSIGN] %s lease=%lu role=%u lease_ms=%lu min_free=%lu caps=0x%02X retry=%u",
      h.id,
      (unsigned long)h.lease_id,
      (unsigned)h.role,
      (unsigned long)LEASE_MS,
      (unsigned long)MIN_FREE,
      (unsigned)h.required_caps,
      (unsigned)h.assign_retries);

  h.assign_pending = true;
  h.assign_last_send_ms = millis();
  h.assign_retries++;
  h.lease_deadline_ms = millis() + LEASE_MS;
}

static void ensureLease(HelperLink& h) {
  if (!g_mq.connected) return;

  // expired?
  if (h.leased && h.lease_deadline_ms && (int32_t)(millis() - h.lease_deadline_ms) > 0) {
    h.leased = false;
    h.assign_pending = false;
    h.lease_id = 0;
  }

  if (h.leased) return;
  // IMPORTANT: main must NOT auto-assign unless discovery explicitly requested it.
  // We only resend if an assign is already pending.
  if (!h.assign_pending) return;
  const uint32_t now = millis();
  const uint32_t RESEND_MS = 400;

  if ((uint32_t)(now - h.assign_last_send_ms) > RESEND_MS && h.assign_retries < 6) {
    sendAssign(h);
  }
}

// -------------------- Cached config publish --------------------
static void publishCfgIfNeeded(HelperLink& h) {
  if (!g_has_keys) return;
  if (!h.leased || !h.online) return;

  // Non-retained CFG. We'll wait for helper cfg/ack (4B key_id) before RUN.
  const uint32_t now = millis();
  if (h.cfg_acked) return;
  if (h.cfg_sent_at && (now - h.cfg_sent_at) < CFG_RETRY_MS) return;

  h.cfg_sent = true;
  h.cfg_key_id_sent = g_key_id;
  h.cfg_sent_at = now;

  // Build single-frame protocol CFG (KPROTO_T_CFG) and publish to per-helper cfg topic.
  uint8_t frame[KPROTO_HDR_LEN + 768]; // enough for SET_T (768B)
  uint16_t flen = 0;

  if (strcmp(h.id, "helper1") == 0) {
    flen = kproto_build(frame, sizeof(frame),
                        KPROTO_T_CFG, KOP_SET_SEED, 0,
                        0 /*job_id*/, g_key_id,
                        g_seed32, (uint16_t)sizeof(g_seed32));
  } else {
    flen = kproto_build(frame, sizeof(frame),
                        KPROTO_T_CFG, KOP_SET_T, 0,
                        0 /*job_id*/, g_key_id,
                        g_t_bytes, (uint16_t)sizeof(g_t_bytes));
  }

  if (flen) {
    g_mq.enqueue(h.t_cfg, frame, flen, 1, false /*retain*/);
  }
}

// -------------------- Job request/response --------------------
static bool sendReq(HelperLink& h, uint32_t job_id, uint8_t op, const uint8_t* sp_raw) {
  if (!g_mq.connected) return false;
  if (!h.leased) return false;
  // one outstanding job per helper: do not overwrite last_req_* until previous completes
  if (h.last_req_valid && !h.res_ready) return false;

  if (!h.cfg_acked) return false;

  // build request frame: payload = sp_raw (192 bytes)
  uint16_t flen = kproto_build(g_frame_buf, (uint16_t)sizeof(g_frame_buf),
                              KPROTO_T_REQ, op, 0,
                              job_id, g_key_id,
                              sp_raw, (uint16_t)SP_PACKED_BYTES);
  if (!flen) return false;

  //if (!g_mq.enqueue(h.t_req, g_frame_buf, flen, KYBER_JOB_QOS, false)) return false;
  if (!g_mq.enqueue(h.t_req, g_frame_buf, flen, KYBER_JOB_QOS, false)) {
  LOGLN("[REQ_ENQ_FAIL] %s job=%lu op=%u flen=%u qos=%u",
        h.id, (unsigned long)job_id, (unsigned)op, (unsigned)flen, (unsigned)KYBER_JOB_QOS);
  return false;
}

  // store last request for potential resend
  memcpy(h.last_req_payload, sp_raw, SP_PACKED_BYTES);
  h.last_req_job = job_id;
  h.last_req_op  = op;
  h.last_req_key = g_key_id;
  h.last_req_valid = true;

  h.res_ready = false;
  h.res_len = 0;

  h.t_start_us = micros();
  h.t_req_sent_us = h.t_start_us;
  h.t_res_first_us = 0;
  h.t_res_done_us = 0;
  return true;
}

static bool resendLastReqIfPossible(HelperLink& h, uint32_t min_gap_ms = 30) {
  if (!h.last_req_valid) return false;
  if (!g_mq.connected || !h.leased) return false;
  const uint32_t now = millis();
  if ((uint32_t)(now - h.last_retry_ms) < min_gap_ms) return false;
  h.last_retry_ms = now;

  uint16_t flen = kproto_build(g_frame_buf, (uint16_t)sizeof(g_frame_buf),
                              KPROTO_T_REQ, h.last_req_op, 0,
                              h.last_req_job, h.last_req_key,
                              h.last_req_payload, (uint16_t)SP_PACKED_BYTES);
  if (!flen) return false;
  return g_mq.enqueue(h.t_req, g_frame_buf, flen, KYBER_JOB_QOS, false);
}

// -------------------- RX dispatch --------------------
static void onMgmtAck(HelperLink& h, const uint8_t* p, uint16_t len) {
  uint32_t lease_id=0; uint8_t code=0;
  if (!mgmt_parse_assign_ack(p, len, &lease_id, &code)) return;
  if (lease_id != h.lease_id) return;

  if (code == MGMT_ACK_OK) {
    h.leased = true;
    h.assign_pending = false;
    // keep cfg_sent as-is; retained cfg will survive anyway
    LOGLN("[MGMT] %s leased lease_id=%lu", h.id, (unsigned long)h.lease_id);
  } else {
    h.leased = false;
    h.assign_pending = false;
    h.lease_id = 0;
    LOGLN("[MGMT] %s assign rejected code=%u", h.id, (unsigned)code);
  }
}

static void onKyberRes(const char* helper_id, const uint8_t* p, uint16_t len) {
  HelperLink* h = nullptr;
  if (strcmp(helper_id, H1.id)==0) h=&H1;
  else if (strcmp(helper_id, H2.id)==0) h=&H2;
  if (!h) return;

  kproto_view_t v;
  if (!kproto_parse(p, len, &v)) return;

  // We only have one outstanding job per helper (by design).
  // So we only accept frames that match the last request (job_id + op + key_id).
  if (!h->last_req_valid) return;
  if (v.key_id != h->last_req_key) return;

  if (v.type == KPROTO_T_NACK) {
    // ignore stale NACK
    if (v.job_id != h->last_req_job || v.op != h->last_req_op) return;

    if (v.payload_len >= 1) {
      const uint8_t code = v.payload[0];

      // If helper asks for config, republish cfg (retained) and resend the same job quickly.
      if (code == KERR_NEED_SEED || code == KERR_NEED_T || code == KERR_KEY_MISMATCH) {
        // Helper is out-of-sync (rebooted / lost cfg). Abort this iteration and re-enter BOOT at the next safe-point.
        g_abort_iteration = true;
        g_defer_boot = true;
      }
    }
    return;
  }

  if (v.type != KPROTO_T_RES) return;
  if (v.job_id != h->last_req_job) return;
  if (v.op != h->last_req_op) return;

  // basic length guard
  /*if (v.payload_len > h->res_cap) return;

  // save first-arrival timestamp
  if (!h->t_res_first_us) h->t_res_first_us = micros();

  // copy payload
  memcpy(h->res_buf, v.payload, v.payload_len);
  h->res_len = v.payload_len;
  h->t_res_done_us = micros();
  h->res_ready = true;*/

  const uint16_t result_len = h->res_cap;
  const uint16_t expected_payload_len = result_len + 4;

  // response must be: result || comp_us
  if (v.payload_len != expected_payload_len) return;

  // arrival/done timestamp
  if (!h->t_res_first_us) h->t_res_first_us = micros();
  h->t_res_done_us = micros();

  // first part is actual Kyber result
  memcpy(h->res_buf, v.payload, result_len);
  h->res_len = result_len;

  // last 4 bytes are helper compute time
  h->helper_comp_us = proto_rd_u32(v.payload + result_len);

  // RTT from main's request timestamp to response processing time
  h->rtt_us = h->t_res_done_us - h->t_req_sent_us;

  // communication overhead = RTT - helper compute time
  if (h->rtt_us >= h->helper_comp_us) {
    h->comm_oh_us = h->rtt_us - h->helper_comp_us;
  } else {
    h->comm_oh_us = 0;
  }

  h->res_ready = true;
}

static bool parseHelperIdFromResTopic(const char* topic, char* out_id, size_t outn) {
  // topic must be: kyber/<id>/res
  if (!topic) return false;
  if (strncmp(topic, "kyber/", 6) != 0) return false;
  const char* p = topic + 6;
  const char* slash = strchr(p, '/');
  if (!slash) return false;
  const size_t idlen = (size_t)(slash - p);
  if (idlen == 0 || idlen >= outn) return false;
  memcpy(out_id, p, idlen);
  out_id[idlen] = 0;
  if (strcmp(slash, "/res") != 0) return false;
  return true;
}
static bool g_need_helpers = true;
static bool g_disc_active = false;
static uint32_t g_last_nohelper_ms = 0;
static const uint16_t DISC_WINDOW_MS = 6000;

static void applySelectedHelpers(const char* id_b, const char* id_v) {
  // Re-init helper links with selected IDs (topics depend on helper id)
  initHelper(H1, id_b, MGMT_CAP_B, 1, "cfg/seed", g_b_bytes, (uint16_t)sizeof(g_b_bytes));
  initHelper(H2, id_v, MGMT_CAP_V, 2, "cfg/t",    g_v_bytes, (uint16_t)sizeof(g_v_bytes));

  // Ask selected helpers to lease
  sendAssign(H1);
  sendAssign(H2);
}


// Enter BOOT phase (stop benchmark, restart discovery/handshake)
static void enterBoot(const char* reason) {
  (void)reason;
#if BENCH_VERBOSE
  LOGLN("[BOOT] enterBoot: %s", reason ? reason : "");
#endif
  g_phase = PHASE_BOOT;
  g_cfgSent = false;
  g_rxDrained = false;
  g_cfgSentAt = 0;
  g_bench_reset = true;
  g_defer_boot = false;
  g_abort_iteration = false;
  H1.cfg_acked = false; H2.cfg_acked = false;
  H1.cfg_sent = false;  H2.cfg_sent = false;
  H1.cfg_sent_at = 0;   H2.cfg_sent_at = 0;

  // reset discovery state so tickDiscovery restarts
  g_need_helpers = true;
  g_disc_active = false;

  // stop discovery session (drop cached offers) if any
  g_mgmt.reset();
}

// Drive BOOT progression and switch to RUN when all conditions are satisfied
static void mgmt_driver_tick(uint32_t now) {
  if (g_phase != PHASE_BOOT) return;

  // Discovery + lease maintenance + cfg publishing
  tickDiscovery();
  ensureLease(H1);
  ensureLease(H2);

  if (g_mq.connected && g_has_keys) {
    publishCfgIfNeeded(H1);
    publishCfgIfNeeded(H2);
  }

  // Condition 1+2: both helpers leased (leased is set only after ACK)
  if (!H1.leased || !H2.leased) return;

  // Condition 3: helpers configured (CFG is non-retained + ACKed)
  if (!H1.cfg_acked || !H2.cfg_acked) {
    // Only send cfg after both helpers are ONLINE and lease-valid (prevents "cfg before connect")
    publishCfgIfNeeded(H1);
    publishCfgIfNeeded(H2);
    return;
  }

  // Condition 4: settle time after cfg ACK (avoid leftover retained/stale traffic)
  if (!g_cfgSent) { g_cfgSent = true; g_cfgSentAt = now; }
  if ((now - g_cfgSentAt) < CFG_SETTLE_MS) return;

  // Before entering RUN, purge any old kyber/*/res still queued.
  drainRxQueue();

  // Condition 5:// Condition 5: mgmt messages done (discovery stopped)
  if (g_need_helpers) return;
  if (g_disc_active) return;

  // All good -> RUN
  g_phase = PHASE_RUN;
#if BENCH_VERBOSE
  LOGLN("[BOOT] -> [RUN] start benchmark");
#endif
}

static void tickDiscovery() {
  if (g_phase != PHASE_BOOT) return;

  if (!g_mq.connected) return;
  if (!g_has_keys) return;

  if (H1.leased && H2.leased) { g_need_helpers = false; g_disc_active = false; return; }
  if (!g_need_helpers) return;

  if (!g_disc_active) {
    g_mgmt.begin(&g_mq);
    (void)g_mgmt.startDiscovery((uint8_t)(MGMT_CAP_B | MGMT_CAP_V), 7000, DISC_WINDOW_MS);
    g_disc_active = true;
  }

  g_mgmt.tick();

  if (g_mgmt.expired()) {
    g_disc_active = false;

    char id_b[16] = {0};
    char id_v[16] = {0};

    if (g_mgmt.pickTwo(id_b, sizeof(id_b), id_v, sizeof(id_v))) {
      applySelectedHelpers(id_b, id_v);
    } else {
      const uint32_t now = millis();
      if ((uint32_t)(now - g_last_nohelper_ms) >= 3000) {
        g_last_nohelper_ms = now;
        LOGLN("no helper found ");
      }
    }
  }
}
// -------------------- Offload API (C ABI) --------------------
extern "C" {

void kyber_offload_poll(void) {
  // Keep pumping TX with a small budget (prevents bursts that starve WiFi)
  static uint32_t last_pump_ms = 0;
  const uint32_t now = millis();
  if ((uint32_t)(now - last_pump_ms) >= 1) {
    last_pump_ms = now;
    g_mq.pumpTx();
  }

const uint32_t now2 = now;

// BOOT: run mgmt state machine; RUN: stay quiet (no mgmt/help)
if (g_phase == PHASE_BOOT) {
  mgmt_driver_tick(now2);
} else {
  // still track lease expiry; if any helper lease is lost -> re-bootstrap
  ensureLease(H1);
  ensureLease(H2);
  if (!H1.leased || !H2.leased) {
    enterBoot("lease lost");
  }
}

// In RUN we still may need cfg publish after key reload (safe/no spam)
if (g_mq.connected && g_has_keys) {
  publishCfgIfNeeded(H1);
  publishCfgIfNeeded(H2);
}

// RX dispatch
  MqttRxItem it;
  for (uint8_t k=0; k<64; k++) {
    if (!g_mq.popRx(it)) break;

    
    // cfg ACK: kyber/helperX/cfg/ack payload = uint32_t key_id (LE)
    if (strncmp(it.topic, "kyber/helper1/cfg/ack", 20) == 0 && it.len == 4) {
      uint32_t kid = (uint32_t)it.data[0] | ((uint32_t)it.data[1] << 8) | ((uint32_t)it.data[2] << 16) | ((uint32_t)it.data[3] << 24);
      if (kid == g_key_id) H1.cfg_acked = true;
      continue;
    }
    if (strncmp(it.topic, "kyber/helper2/cfg/ack", 20) == 0 && it.len == 4) {
      uint32_t kid = (uint32_t)it.data[0] | ((uint32_t)it.data[1] << 8) | ((uint32_t)it.data[2] << 16) | ((uint32_t)it.data[3] << 24);
      if (kid == g_key_id) H2.cfg_acked = true;
      continue;
    }

// status plane (LWT): status/helper1|helper2 = online/offline (retained)
    if (strncmp(it.topic, "status/helper1", 14) == 0) {
      bool online = (it.len == 6 && memcmp(it.data, "online", 6) == 0);
      g_h1_online = online;
      H1.online = online;
      if (!online) g_abort_iteration = true;
      continue;
    }
    if (strncmp(it.topic, "status/helper2", 14) == 0) {
      bool online = (it.len == 6 && memcmp(it.data, "online", 6) == 0);
      g_h2_online = online;
      H2.online = online;
      if (!online) g_abort_iteration = true;
      continue;
    }


if (strncmp(it.topic, "mgmt/offer/", 11) == 0) {
  const char* hid = it.topic + 11;

  if (g_phase == PHASE_RUN) {
  // در RUN offer را نادیده بگیر؛ فقط lease-lost تصمیم‌گیر است
  continue;
}

  // During kyber bursts, don't let offers starve kyber RX processing.
  if (g_kyber_busy) continue;

  g_mgmt.onOffer(hid, it.data, it.len);
  continue;
}
    if (strncmp(it.topic, "mgmt/ack/", 9) == 0) {
      const char* hid = it.topic + 9;
      if (strcmp(hid, H1.id) == 0) onMgmtAck(H1, it.data, it.len);
      else if (strcmp(hid, H2.id) == 0) onMgmtAck(H2, it.data, it.len);
      continue;
    }

    if (strncmp(it.topic, "kyber/", 6) == 0) {
      char hid[16];
      if (parseHelperIdFromResTopic(it.topic, hid, sizeof(hid))) {
        onKyberRes(hid, it.data, it.len);
      }
      continue;
    }

    if ((k & 0x07) == 0x07) delay(0);
  }
  delay(0);
}

int kyber_offload_request_b(const uint8_t seed32[32], const uint8_t sp_raw[], uint32_t* job_id) {
  (void)seed32; // seed is cached in helper1 via retained cfg
  if (!job_id) return -1;
  if (!H1.leased) return -2;

  const uint32_t jid = allocJobId();
  if (!sendReq(H1, jid, KOP_B, sp_raw)) return -3;
  *job_id = jid;
  return 0;
}

int kyber_offload_request_v(const uint8_t pkpv_bytes[], const uint8_t sp_raw[], uint32_t* job_id) {
  (void)pkpv_bytes; // t is cached in helper2 via retained cfg
  if (!job_id) return -1;
  if (!H2.leased) return -2;

  const uint32_t jid = allocJobId();
  if (!sendReq(H2, jid, KOP_V, sp_raw)) return -3;
  *job_id = jid;
  return 0;
}
} // extern "C"
static int waitResultFrom(HelperLink& h, uint32_t job_id, uint8_t expected_op, uint8_t* out, uint16_t outlen, uint32_t timeout_ms)
{
  // Guard: this main implementation supports one outstanding job per helper.
  if (!h.last_req_valid) return -4;
  if (h.last_req_job != job_id) return -4;
  if (h.last_req_op  != expected_op) return -4;
  if (h.last_req_key != g_key_id) return -4;

  const uint32_t t0 = millis();
  // Safe-point abort: if helper dropped (status/LWT), stop waiting immediately
  if (g_abort_iteration) return -7;
  if ((h.role == 1 && !g_h1_online) || (h.role == 2 && !g_h2_online)) { g_abort_iteration = true; return -7; }

  uint32_t last_relax_ms = t0;
  bool did_resend = false;
  //bool resent_once = false;
  while ((uint32_t)(millis() - t0) < timeout_ms) {
    if (!g_mq.connected) return -2;
    if (!h.leased) return -5;

    kyber_offload_poll();
    // <<< ADD THIS LINE >>>
    iot_load_slice();

    const uint32_t now_ms = millis();
    if ((uint32_t)(now_ms - last_relax_ms) >= 20) {
      last_relax_ms = now_ms;
      delay(1);
    } else {
      delay(0);
    }

    // If response arrived, validate and return
    if (h.res_ready) {
      if (h.res_len == outlen) {
        memcpy(out, h.res_buf, outlen);
        h.res_ready = false;
        h.last_req_valid = false;
        return 0;
      }
      h.res_ready = false;
      h.last_req_valid = false;
      return -3;
    }

    // If we're using QoS0, a small periodic resend helps fight rare WiFi loss
/*#if (KYBER_JOB_QOS == 0)
    if ((uint32_t)(millis() - t0) > 250) {
      (void)resendLastReqIfPossible(h, 250);
    }
#endif*/
#if (KYBER_JOB_QOS == 0)
  if (!did_resend && !h.t_res_first_us && (uint32_t)(millis() - t0) > 300) {
    did_resend = resendLastReqIfPossible(h, 300);
  }
#endif
/*#if (KYBER_JOB_QOS == 0)
    // اگر هنوز هیچ res نیومده و فقط یکبار هم اجازه داری
    const uint32_t elapsed = (uint32_t)(millis() - t0);
    if (!resent_once && !h.t_res_first_us && elapsed > 280) {
      (void)resendLastReqIfPossible(h, 280);
      resent_once = true;
    }
#endif*/
    delay(0);
  }
  h.last_req_valid = false; // timeout ends this outstanding job
  return -1;
}
extern "C" {
int kyber_offload_wait_b(uint32_t job_id, uint8_t b_out[]) {
  if (!b_out) return -1;
  return waitResultFrom(H1, job_id, KOP_B, b_out, (uint16_t)KYBER_POLYVECBYTES, KYBER_JOB_TIMEOUT_MS);
}

int kyber_offload_wait_v(uint32_t job_id, uint8_t v_out[]) {
  if (!v_out) return -1;
  return waitResultFrom(H2, job_id, KOP_V, v_out, (uint16_t)KYBER_POLYBYTES, KYBER_JOB_TIMEOUT_MS);
}

} // extern "C"

// -------------------- Demo: encaps/decaps once --------------------
static void printPhaseSummary(const char* tag, int rc, uint32_t t_us) {
  Serial.printf("%s rc=%d time_us=%lu\n", tag, rc, (unsigned long)t_us);

  // optional: show helper timing breakdown if needed
  if (H1.t_start_us && H1.t_res_done_us) {
    Serial.printf("  H1 total_us=%lu\n", (unsigned long)(H1.t_res_done_us - H1.t_start_us));
  }
  if (H2.t_start_us && H2.t_res_done_us) {
    Serial.printf("  H2 total_us=%lu\n", (unsigned long)(H2.t_res_done_us - H2.t_start_us));
  }
}
//یکبار اجرا
/*static bool g_sent_once = false;
static void tryEncapsOnce() {
  if (!g_has_keys) return;
  if (!H1.leased || !H2.leased) return;
  if (g_sent_once) return;

  static uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  static uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
  static uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

  delay(0);

  g_kyber_busy = true;
  uint32_t t0 = micros();
  int rc1 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, g_pk);
  uint32_t t_enc = micros() - t0;
  g_kyber_busy = false;
  printPhaseSummary("ENC", rc1, t_enc);

  if (rc1 != 0) { g_sent_once = true; return; }

  delay(10);

  g_kyber_busy = true;
  uint32_t d0 = micros();
  int rc2 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, g_sk);
  uint32_t t_dec = micros() - d0;
  g_kyber_busy = false;
  printPhaseSummary("DEC", rc2, t_dec);

  if (rc2 != 0) { g_sent_once = true; return; }

  if (memcmp(ss1, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES) == 0) Serial.println("KEM_OK (SS MATCH)");
  else Serial.println("KEM_BAD (SS MISMATCH)");

  g_sent_once = true;
}*/
//10 بار اجرا
static const uint16_t KEM_RUNS = 10;
static uint16_t g_kem_i = 0;
static bool g_kem_done = false;

static void tryEncapsOnce() {
  if (!g_has_keys) return;
  if (!H1.leased || !H2.leased) return;
  if (g_kem_done) return;

  if (g_kem_i >= KEM_RUNS) {
    g_kem_done = true;
    Serial.printf("[KEM] done, runs=%u\n", (unsigned)KEM_RUNS);
    return;
  }

  // (اختیاری اما مفید) تایمینگ هلپرها رو برای این ران صفر کن که
  // printPhaseSummary از ران قبلی چیزی نشون نده
  H1.t_start_us = H1.t_res_done_us = 0;
  H2.t_start_us = H2.t_res_done_us = 0;

  Serial.printf("\n[RUN %u/%u]\n", (unsigned)(g_kem_i + 1), (unsigned)KEM_RUNS);

  static uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  static uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
  static uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

  delay(0);

  g_kyber_busy = true;
  uint32_t t0 = micros();
  int rc1 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, g_pk);
  uint32_t t_enc = micros() - t0;
  g_kyber_busy = false;
  printPhaseSummary("ENC", rc1, t_enc);

  if (rc1 != 0) { g_kem_done = true; return; }

  delay(10);

  g_kyber_busy = true;
  uint32_t d0 = micros();
  int rc2 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, g_sk);
  uint32_t t_dec = micros() - d0;
  g_kyber_busy = false;
  printPhaseSummary("DEC", rc2, t_dec);

  if (rc2 != 0) { g_kem_done = true; return; }

  if (memcmp(ss1, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES) == 0) Serial.println("KEM_OK (SS MATCH)");
  else Serial.println("KEM_BAD (SS MISMATCH)");

  g_kem_i++;
}

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\nBOOT(main)");
  Serial.printf("free heap=%u\n", ESP.getFreeHeap());

  initHelper(H1, H1_ID, MGMT_CAP_B, 1, "cfg/seed", g_b_bytes, (uint16_t)sizeof(g_b_bytes));
  initHelper(H2, H2_ID, MGMT_CAP_V, 2, "cfg/t",    g_v_bytes, (uint16_t)sizeof(g_v_bytes));

  static char clientId[32];
  snprintf(clientId, sizeof(clientId), "ESP_%s", MAIN_ID);

  g_mq.setWifiCred(WIFI_SSID, WIFI_PASS);
  g_mq.begin(MQTT_HOST, MQTT_PORT, clientId);

  // lower latency during kyber bursts
  g_mq.kyberBurstEnable(true);
  g_mq.kyberBurstSetHoldMs(220);

  g_mq.onConnChange = [](bool up){
    LOGLN(up ? "[MQTT] connected" : "[MQTT] disconnected");
    LOGLN("[WIFI] rssi=%d dBm", (int)WiFi.RSSI());
  };

  // subscribe: results from helpers + mgmt acks
  g_mq.subscribe("kyber/+/res", 1);
  g_mq.subscribe("kyber/+/cfg/ack", 1);
  g_mq.subscribe("mgmt/ack/#",  1);
  g_mq.subscribe("mgmt/offer/#", 1);
  g_mq.subscribe("status/#",    1);
  // keys
  g_has_keys = loadKeysOrMake();
  Serial.println(g_has_keys ? "KEYS_OK" : "KEYS_FAIL");
  if (g_has_keys) deriveKeyParts();

  WiFi.setSleepMode(WIFI_NONE_SLEEP);
  Serial.println();
}

// Drain all pending RX messages (used when switching BOOT -> RUN)
static void drainRxQueue() {
  MqttRxItem it;
  while (g_mq.popRx(it)) {
    // drop
  }
}


// ---------- stats helpers ----------
/*static void sort_u32(uint32_t* a, int n) {
  // insertion sort (n is small)
  for (int i = 1; i < n; i++) {
    uint32_t key = a[i];
    int j = i - 1;
    while (j >= 0 && a[j] > key) { a[j + 1] = a[j]; j--; }
    a[j + 1] = key;
  }
}*/

// Nearest-rank percentile (p in [0,1]), e.g. p=0.5 median, p=0.9 p90
/*static uint32_t percentile_u32(const uint32_t* a_in, int n, float p) {
  if (n <= 0) return 0;
  if (p <= 0.0f) return a_in[0];
  if (p >= 1.0f) return a_in[n - 1];
  // copy then sort
  uint32_t tmp[64];
  if (n > (int)(sizeof(tmp)/sizeof(tmp[0]))) n = (int)(sizeof(tmp)/sizeof(tmp[0]));
  for (int i = 0; i < n; i++) tmp[i] = a_in[i];
  sort_u32(tmp, n);
  int rank = (int)ceilf(p * n); // 1..n
  if (rank < 1) rank = 1;
  if (rank > n) rank = n;
  return tmp[rank - 1];
}*/
static uint32_t stddev_u32(const uint32_t* a, int n, uint32_t avg) {
  if (n <= 1) return 0;

  double ss = 0.0;
  for (int i = 0; i < n; i++) {
    double diff = (double)a[i] - (double)avg;
    ss += diff * diff;
  }

  double var = ss / (double)(n - 1);   // sample standard deviation
  return (uint32_t)(sqrt(var) + 0.5);
}
static inline uint32_t max_u32(uint32_t a, uint32_t b) {
  return (a > b) ? a : b;
}

static inline uint32_t sub_u32_safe(uint32_t a, uint32_t b) {
  return (a >= b) ? (a - b) : 0;
}
static void benchSweepIfReady() {
  static const uint8_t loads[] = {0,10,20,30,40,50,60,70,80,90};
  static uint8_t idx = 0;
  static bool done = false;
  static uint8_t batch_no = 0;
  static const uint8_t MAX_BATCHES = 10;
  const int N = 10;
  static uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
  static uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
  static uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

  if (done) return;
  if (g_phase != PHASE_RUN) return;
  if (!g_cfgSent) return;
  if (!g_has_keys) return;
  if (!H1.leased || !H2.leased) return;

  /*if (idx >= sizeof(loads)) {
    Serial.println("\n[DONE] All loads tested.");
    done = true;
    return;
  }*/
  /*if (idx >= sizeof(loads)) {
    Serial.println("\n[DONE] All loads tested.");
    Serial.println("[WAIT] next batch in 10 seconds...");
    delay(10000);

    idx = 0;
    done = false;

    drainRxQueue();
    H1.last_req_valid = false;
    H2.last_req_valid = false;
    H1.res_ready = false;
    H2.res_ready = false;

    H1.helper_comp_us = H1.rtt_us = H1.comm_oh_us = 0;
    H2.helper_comp_us = H2.rtt_us = H2.comm_oh_us = 0;

    return;
  }*/
  if (idx >= sizeof(loads)) {
    batch_no++;

    Serial.printf("\n[DONE] Batch %u/%u completed.\n",
                (unsigned)batch_no,
                (unsigned)MAX_BATCHES);

    if (batch_no >= MAX_BATCHES) {
      Serial.println("[DONE] All batches completed.");
      done = true;
      return;
    }

    Serial.println("[WAIT] next batch in 10 seconds...");
    delay(10000);

    drainRxQueue();

    H1.last_req_valid = false;
    H2.last_req_valid = false;
    H1.res_ready = false;
    H2.res_ready = false;

    H1.helper_comp_us = H1.rtt_us = H1.comm_oh_us = 0;
    H2.helper_comp_us = H2.rtt_us = H2.comm_oh_us = 0;

    idx = 0;
    return;
  }

  uint8_t p = loads[idx++];
  g_load = p;

  Serial.printf("\n==============================\n");
  Serial.printf("MAIN Coop IoT load = %u%% | N = %d\n", p, N);
  Serial.printf("==============================\n");

  delay(200);

  uint32_t enc_s[10];
  uint32_t dec_s[10];
  int enc_n = 0, dec_n = 0;

  uint32_t sum_e = 0, sum_d = 0;
  uint32_t min_e = 0xFFFFFFFFu, min_d = 0xFFFFFFFFu;
  uint32_t max_e = 0, max_d = 0;
  uint32_t sum_enc_rtt = 0, sum_dec_rtt = 0;
  uint32_t sum_enc_comp = 0, sum_dec_comp = 0;
  uint32_t sum_enc_oh = 0, sum_dec_oh = 0;

  int ok_cnt = 0;
  int fail_cnt = 0;

  for (int i = 0; i < N; i++) {
    if (g_abort_iteration) {
      Serial.println("[ABORT] helper offline -> BOOT");
      enterBoot("auto");
      return;
    }

    // Before starting a new iteration, drop any stale kyber/*/res left in RX queue
    drainRxQueue();
    H1.last_req_valid = false; H2.last_req_valid = false;
    H1.res_ready = false;      H2.res_ready = false;
    g_kyber_busy = true;
    H1.helper_comp_us = H1.rtt_us = H1.comm_oh_us = 0;
    H2.helper_comp_us = H2.rtt_us = H2.comm_oh_us = 0;
    uint32_t t0 = micros();
    int rc1 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, g_pk);
    uint32_t t_enc = micros() - t0;
    uint32_t enc_rtt_total  = max_u32(H1.rtt_us, H2.rtt_us);
    uint32_t enc_comp_total = max_u32(H1.helper_comp_us, H2.helper_comp_us);
    uint32_t enc_oh_total   = sub_u32_safe(enc_rtt_total, enc_comp_total);


    g_kyber_busy = false;

    if (g_abort_iteration) {
      Serial.println("[ABORT] helper offline during encaps -> BOOT");
      enterBoot("auto");
      return;
    }

    // Before starting a new iteration, drop any stale kyber/*/res left in RX queue
    drainRxQueue();
    H1.last_req_valid = false; H2.last_req_valid = false;
    H1.res_ready = false;      H2.res_ready = false;
    g_kyber_busy = true;
    H1.helper_comp_us = H1.rtt_us = H1.comm_oh_us = 0;
    H2.helper_comp_us = H2.rtt_us = H2.comm_oh_us = 0;
    uint32_t d0 = micros();
    int rc2 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, g_sk);
    uint32_t t_dec = micros() - d0;
    uint32_t dec_rtt_total  = max_u32(H1.rtt_us, H2.rtt_us);
    uint32_t dec_comp_total = max_u32(H1.helper_comp_us, H2.helper_comp_us);
    uint32_t dec_oh_total   = sub_u32_safe(dec_rtt_total, dec_comp_total);

    g_kyber_busy = false;

    bool ok = (rc1 == 0 && rc2 == 0 && memcmp(ss1, ss2, sizeof(ss1)) == 0);

    if (ok) {
      enc_s[enc_n++] = t_enc;
      dec_s[dec_n++] = t_dec;

      ok_cnt++;
      sum_e += t_enc;
      sum_d += t_dec;
      sum_enc_rtt  += enc_rtt_total;
      sum_enc_comp += enc_comp_total;
      sum_enc_oh   += enc_oh_total;

      sum_dec_rtt  += dec_rtt_total;
      sum_dec_comp += dec_comp_total;
      sum_dec_oh   += dec_oh_total;

      if (t_enc < min_e) min_e = t_enc;
      if (t_enc > max_e) max_e = t_enc;
      if (t_dec < min_d) min_d = t_dec;
      if (t_dec > max_d) max_d = t_dec;
    } else {
      fail_cnt++;
      Serial.printf("#%03d enc=%lu us | dec=%lu us | FAIL (rc1=%d rc2=%d)\n",
                    i + 1, (unsigned long)t_enc, (unsigned long)t_dec, rc1, rc2);
    }

    // Cooperative IoT load tick (keeps WiFi/MQTT serviced)
    // keep background IoT load running during bench sweep delays
    iot_load_slice();

    if (g_abort_iteration) {
      Serial.println("[ABORT] helper offline after iteration -> BOOT");
      enterBoot("auto");
      return;
    }
  }

  Serial.println("\n--- Summary ---");
  Serial.printf("OK=%d FAIL=%d\n", ok_cnt, fail_cnt);

  if (ok_cnt > 0) {
    uint32_t avg_e = sum_e / (uint32_t)ok_cnt;
    uint32_t avg_d = sum_d / (uint32_t)ok_cnt;
    uint32_t std_e = stddev_u32(enc_s, enc_n, avg_e);
    uint32_t std_d = stddev_u32(dec_s, dec_n, avg_d);

    /*uint32_t p50_e = percentile_u32(enc_s, enc_n, 0.50f);
    uint32_t p90_e = percentile_u32(enc_s, enc_n, 0.90f);
    uint32_t p99_e = percentile_u32(enc_s, enc_n, 0.99f);

    uint32_t p50_d = percentile_u32(dec_s, dec_n, 0.50f);
    uint32_t p90_d = percentile_u32(dec_s, dec_n, 0.90f);
    uint32_t p99_d = percentile_u32(dec_s, dec_n, 0.99f);*/

    Serial.printf("encaps : avg=%lu us | std=%lu | min=%lu | max=%lu\n",
              (unsigned long)avg_e,
              (unsigned long)std_e,
              (unsigned long)min_e,
              (unsigned long)max_e);

    Serial.printf("decaps : avg=%lu us | std=%lu | min=%lu | max=%lu\n",
              (unsigned long)avg_d,
              (unsigned long)std_d,
              (unsigned long)min_d,
              (unsigned long)max_d);        

    uint32_t avg_enc_rtt  = sum_enc_rtt  / (uint32_t)ok_cnt;
    uint32_t avg_enc_comp = sum_enc_comp / (uint32_t)ok_cnt;
    uint32_t avg_enc_oh   = sum_enc_oh   / (uint32_t)ok_cnt;

    uint32_t avg_dec_rtt  = sum_dec_rtt  / (uint32_t)ok_cnt;
    uint32_t avg_dec_comp = sum_dec_comp / (uint32_t)ok_cnt;
    uint32_t avg_dec_oh   = sum_dec_oh   / (uint32_t)ok_cnt;

    Serial.printf("enc_comm_eff: rtt=%lu us | helper_comp=%lu us | overhead=%lu us\n",
              (unsigned long)avg_enc_rtt,
              (unsigned long)avg_enc_comp,
              (unsigned long)avg_enc_oh);

    Serial.printf("dec_comm_eff: rtt=%lu us | helper_comp=%lu us | overhead=%lu us\n",
              (unsigned long)avg_dec_rtt,
              (unsigned long)avg_dec_comp,
              (unsigned long)avg_dec_oh);

  } else {
    Serial.println("No successful samples in this batch.");
  }
}
void loop() {
  kyber_offload_poll();

  // Only run benchmark in RUN phase
  if (g_phase == PHASE_RUN) {
    benchSweepIfReady();
  }

  delay(0);
}

