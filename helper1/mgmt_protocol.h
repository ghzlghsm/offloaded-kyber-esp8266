#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "protocol.h"   // reuse proto_wr_u32/proto_rd_u32/proto_crc16_ccitt

#define MGMT_VER 2

#ifndef MGMT_HELP_TOPIC
#define MGMT_HELP_TOPIC "mgmt/help"
#endif

#ifndef MGMT_QOS_OFFER
#define MGMT_QOS_OFFER 0   // offer رو QoS0 می‌کنیم
#endif

#ifndef MGMT_QOS_WILL
#define MGMT_QOS_WILL  1   // ولی LWT (offline retained) رو QoS1 نگه می‌داریم
#endif

#ifndef MGMT_OFFER_PERIOD_MS_BUSY
#define MGMT_OFFER_PERIOD_MS_BUSY 10000  // وقتی busy هست: هر 10 ثانیه
#endif


#ifndef MGMT_QOS_CTRL
#define MGMT_QOS_CTRL  1     // assign/ack/release QoS1
#endif

#ifndef MGMT_OFFER_PERIOD_MS
#define MGMT_OFFER_PERIOD_MS 2000
#endif

typedef enum : uint8_t {
  MGMT_OFFER       = 1,
  MGMT_ASSIGN      = 2,
  MGMT_ASSIGN_ACK  = 3,
  MGMT_RELEASE     = 4,

  // NEW (pull-based)
  MGMT_HELP_WANTED = 5,   // main -> all helpers
  MGMT_OFFER_RSP   = 6    // helper -> main (offer پاسخ به help_wanted با req_id)
} mgmt_type_t;


typedef enum : uint8_t {
  MGMT_STATUS_READY   = 0,
  MGMT_STATUS_BUSY    = 1,
  MGMT_STATUS_OFFLINE = 2
} mgmt_status_t;

typedef enum : uint8_t {
  MGMT_CAP_B = 0x01,
  MGMT_CAP_V = 0x02
} mgmt_caps_t;

typedef enum : uint8_t {
  MGMT_ACK_OK      = 0,
  MGMT_ACK_BUSY    = 1,
  MGMT_ACK_BADCAPS = 2,
  MGMT_ACK_LOWMEM  = 3,
  MGMT_ACK_BADCRC  = 4
} mgmt_ack_code_t;

#define MGMT_OFFER_LEN      23
#define MGMT_ASSIGN_LEN     18
#define MGMT_ASSIGN_ACK_LEN 9
#define MGMT_RELEASE_LEN    8

#define MGMT_HELP_WANTED_LEN 18
#define MGMT_OFFER_RSP_LEN   27

#ifndef MGMT_QOS_OFFER_RSP
#define MGMT_QOS_OFFER_RSP 1
#endif


uint16_t mgmt_build_offer(uint8_t out[MGMT_OFFER_LEN],
                          uint32_t uptime_s,
                          uint32_t free_heap,
                          uint32_t max_block,
                          uint8_t frag_pct,
                          uint8_t status,
                          uint8_t caps,
                          uint32_t lease_id);

bool mgmt_parse_offer(const uint8_t* p, uint16_t len,
                      uint32_t* uptime_s, uint32_t* free_heap, uint32_t* max_block,
                      uint8_t* frag_pct, uint8_t* status, uint8_t* caps, uint32_t* lease_id);

uint16_t mgmt_build_assign(uint8_t out[MGMT_ASSIGN_LEN],
                           uint32_t lease_id, uint8_t role, uint32_t lease_ms,
                           uint32_t min_free_heap, uint8_t required_caps);

bool mgmt_parse_assign(const uint8_t* p, uint16_t len,
                       uint32_t* lease_id, uint8_t* role, uint32_t* lease_ms,
                       uint32_t* min_free_heap, uint8_t* required_caps);

uint16_t mgmt_build_assign_ack(uint8_t out[MGMT_ASSIGN_ACK_LEN],
                               uint32_t lease_id, uint8_t code);

bool mgmt_parse_assign_ack(const uint8_t* p, uint16_t len,
                           uint32_t* lease_id, uint8_t* code);

uint16_t mgmt_build_release(uint8_t out[MGMT_RELEASE_LEN],
                            uint32_t lease_id);

bool mgmt_parse_release(const uint8_t* p, uint16_t len,
                        uint32_t* lease_id);
uint16_t mgmt_build_help_wanted(uint8_t out[MGMT_HELP_WANTED_LEN],
                                uint32_t req_id,
                                uint8_t  need_caps,
                                uint32_t min_free_heap,
                                uint16_t window_ms,
                                uint16_t features_mask);

bool mgmt_parse_help_wanted(const uint8_t* p, uint16_t len,
                            uint32_t* req_id,
                            uint8_t*  need_caps,
                            uint32_t* min_free_heap,
                            uint16_t* window_ms,
                            uint16_t* features_mask);

uint16_t mgmt_build_offer_rsp(uint8_t out[MGMT_OFFER_RSP_LEN],
                              uint32_t req_id,
                              uint32_t uptime_s,
                              uint32_t free_heap,
                              uint32_t max_block,
                              uint8_t  frag_pct,
                              uint8_t  status,
                              uint8_t  caps,
                              uint32_t lease_id);

bool mgmt_parse_offer_rsp(const uint8_t* p, uint16_t len,
                          uint32_t* req_id,
                          uint32_t* uptime_s, uint32_t* free_heap, uint32_t* max_block,
                          uint8_t* frag_pct, uint8_t* status, uint8_t* caps, uint32_t* lease_id);
