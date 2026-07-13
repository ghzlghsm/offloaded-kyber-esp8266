#include "mgmt_protocol.h"

static inline void wr_crc16(uint8_t* out, uint16_t off, uint16_t crc) {
  proto_wr_u16(out + off, crc);
}

static inline bool check_crc(const uint8_t* p, uint16_t len) {
  if (len < 3) return false;
  uint16_t rx = proto_rd_u16(p + (len - 2));
  uint16_t cc = proto_crc16_ccitt(p, (uint32_t)(len - 2));
  return rx == cc;
}

uint16_t mgmt_build_offer(uint8_t out[MGMT_OFFER_LEN],
                          uint32_t uptime_s,
                          uint32_t free_heap,
                          uint32_t max_block,
                          uint8_t frag_pct,
                          uint8_t status,
                          uint8_t caps,
                          uint32_t lease_id)
{
  out[0]=MGMT_VER; out[1]=MGMT_OFFER;
  proto_wr_u32(&out[2], uptime_s);
  proto_wr_u32(&out[6], free_heap);
  proto_wr_u32(&out[10], max_block);
  out[14]=frag_pct;
  out[15]=status;
  out[16]=caps;
  proto_wr_u32(&out[17], lease_id);

  uint16_t crc = proto_crc16_ccitt(out, MGMT_OFFER_LEN-2);
  wr_crc16(out, MGMT_OFFER_LEN-2, crc);
  return MGMT_OFFER_LEN;
}

bool mgmt_parse_offer(const uint8_t* p, uint16_t len,
                      uint32_t* uptime_s, uint32_t* free_heap, uint32_t* max_block,
                      uint8_t* frag_pct, uint8_t* status, uint8_t* caps, uint32_t* lease_id)
{
  if (len != MGMT_OFFER_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_OFFER) return false;
  if (!check_crc(p, len)) return false;

  *uptime_s   = proto_rd_u32(&p[2]);
  *free_heap  = proto_rd_u32(&p[6]);
  *max_block  = proto_rd_u32(&p[10]);
  *frag_pct   = p[14];
  *status     = p[15];
  *caps       = p[16];
  *lease_id   = proto_rd_u32(&p[17]);
  return true;
}

uint16_t mgmt_build_assign(uint8_t out[MGMT_ASSIGN_LEN],
                           uint32_t lease_id, uint8_t role, uint32_t lease_ms,
                           uint32_t min_free_heap, uint8_t required_caps)
{
  out[0]=MGMT_VER; out[1]=MGMT_ASSIGN;
  proto_wr_u32(&out[2], lease_id);
  out[6]=role;
  proto_wr_u32(&out[7], lease_ms);
  proto_wr_u32(&out[11], min_free_heap);
  out[15]=required_caps;

  uint16_t crc = proto_crc16_ccitt(out, MGMT_ASSIGN_LEN-2);
  wr_crc16(out, MGMT_ASSIGN_LEN-2, crc);
  return MGMT_ASSIGN_LEN;
}

bool mgmt_parse_assign(const uint8_t* p, uint16_t len,
                       uint32_t* lease_id, uint8_t* role, uint32_t* lease_ms,
                       uint32_t* min_free_heap, uint8_t* required_caps)
{
  if (len != MGMT_ASSIGN_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_ASSIGN) return false;
  if (!check_crc(p, len)) return false;

  *lease_id = proto_rd_u32(&p[2]);
  *role = p[6];
  *lease_ms = proto_rd_u32(&p[7]);
  *min_free_heap = proto_rd_u32(&p[11]);
  *required_caps = p[15];
  return true;
}

uint16_t mgmt_build_assign_ack(uint8_t out[MGMT_ASSIGN_ACK_LEN],
                               uint32_t lease_id, uint8_t code)
{
  out[0]=MGMT_VER; out[1]=MGMT_ASSIGN_ACK;
  proto_wr_u32(&out[2], lease_id);
  out[6]=code;

  uint16_t crc = proto_crc16_ccitt(out, MGMT_ASSIGN_ACK_LEN-2);
  wr_crc16(out, MGMT_ASSIGN_ACK_LEN-2, crc);
  return MGMT_ASSIGN_ACK_LEN;
}

bool mgmt_parse_assign_ack(const uint8_t* p, uint16_t len,
                           uint32_t* lease_id, uint8_t* code)
{
  if (len != MGMT_ASSIGN_ACK_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_ASSIGN_ACK) return false;
  if (!check_crc(p, len)) return false;

  *lease_id = proto_rd_u32(&p[2]);
  *code = p[6];
  return true;
}

uint16_t mgmt_build_release(uint8_t out[MGMT_RELEASE_LEN],
                            uint32_t lease_id)
{
  out[0]=MGMT_VER; out[1]=MGMT_RELEASE;
  proto_wr_u32(&out[2], lease_id);

  uint16_t crc = proto_crc16_ccitt(out, MGMT_RELEASE_LEN-2);
  wr_crc16(out, MGMT_RELEASE_LEN-2, crc);
  return MGMT_RELEASE_LEN;
}

bool mgmt_parse_release(const uint8_t* p, uint16_t len,
                        uint32_t* lease_id)
{
  if (len != MGMT_RELEASE_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_RELEASE) return false;
  if (!check_crc(p, len)) return false;

  *lease_id = proto_rd_u32(&p[2]);
  return true;
}
uint16_t mgmt_build_help_wanted(uint8_t out[MGMT_HELP_WANTED_LEN],
                                uint32_t req_id,
                                uint8_t  need_caps,
                                uint32_t min_free_heap,
                                uint16_t window_ms,
                                uint16_t features_mask)
{
  out[0]=MGMT_VER; out[1]=MGMT_HELP_WANTED;
  proto_wr_u32(&out[2], req_id);
  out[6] = need_caps;
  out[7] = 0; // flags reserved
  proto_wr_u32(&out[8], min_free_heap);
  proto_wr_u16(&out[12], window_ms);
  proto_wr_u16(&out[14], features_mask);

  uint16_t crc = proto_crc16_ccitt(out, MGMT_HELP_WANTED_LEN-2);
  wr_crc16(out, MGMT_HELP_WANTED_LEN-2, crc);
  return MGMT_HELP_WANTED_LEN;
}

bool mgmt_parse_help_wanted(const uint8_t* p, uint16_t len,
                            uint32_t* req_id,
                            uint8_t*  need_caps,
                            uint32_t* min_free_heap,
                            uint16_t* window_ms,
                            uint16_t* features_mask)
{
  if (len != MGMT_HELP_WANTED_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_HELP_WANTED) return false;
  if (!check_crc(p, len)) return false;

  *req_id        = proto_rd_u32(&p[2]);
  *need_caps     = p[6];
  *min_free_heap = proto_rd_u32(&p[8]);
  *window_ms     = proto_rd_u16(&p[12]);
  *features_mask = proto_rd_u16(&p[14]);
  return true;
}

uint16_t mgmt_build_offer_rsp(uint8_t out[MGMT_OFFER_RSP_LEN],
                              uint32_t req_id,
                              uint32_t uptime_s,
                              uint32_t free_heap,
                              uint32_t max_block,
                              uint8_t  frag_pct,
                              uint8_t  status,
                              uint8_t  caps,
                              uint32_t lease_id)
{
  out[0]=MGMT_VER; out[1]=MGMT_OFFER_RSP;
  proto_wr_u32(&out[2], req_id);
  proto_wr_u32(&out[6], uptime_s);
  proto_wr_u32(&out[10], free_heap);
  proto_wr_u32(&out[14], max_block);
  out[18]=frag_pct;
  out[19]=status;
  out[20]=caps;
  proto_wr_u32(&out[21], lease_id);

  uint16_t crc = proto_crc16_ccitt(out, MGMT_OFFER_RSP_LEN-2);
  wr_crc16(out, MGMT_OFFER_RSP_LEN-2, crc);
  return MGMT_OFFER_RSP_LEN;
}

bool mgmt_parse_offer_rsp(const uint8_t* p, uint16_t len,
                          uint32_t* req_id,
                          uint32_t* uptime_s, uint32_t* free_heap, uint32_t* max_block,
                          uint8_t* frag_pct, uint8_t* status, uint8_t* caps, uint32_t* lease_id)
{
  if (len != MGMT_OFFER_RSP_LEN) return false;
  if (p[0] != MGMT_VER || p[1] != MGMT_OFFER_RSP) return false;
  if (!check_crc(p, len)) return false;

  *req_id     = proto_rd_u32(&p[2]);
  *uptime_s   = proto_rd_u32(&p[6]);
  *free_heap  = proto_rd_u32(&p[10]);
  *max_block  = proto_rd_u32(&p[14]);
  *frag_pct   = p[18];
  *status     = p[19];
  *caps       = p[20];
  *lease_id   = proto_rd_u32(&p[21]);
  return true;
}
