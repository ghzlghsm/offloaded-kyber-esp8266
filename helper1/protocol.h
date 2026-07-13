// ========================= protocol.h (single-frame Kyber offload) =========================
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// This header provides:
//  - small endian helpers (proto_wr_u16/u32, proto_rd_u16/u32) used by mgmt_protocol too
//  - CRC16-CCITT (same polynomial 0x1021, init 0xFFFF)
//  - a single-frame (non-chunked) Kyber offload wire format with build/parse helpers
//
// NOTE: This replaces the old META/DATA/ACK chunk protocol completely.

// -------------------- Endian helpers (little-endian on wire) --------------------
static inline void proto_wr_u16(uint8_t* p, uint16_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static inline void proto_wr_u32(uint8_t* p, uint32_t v){ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static inline uint16_t proto_rd_u16(const uint8_t* p){ return (uint16_t)p[0] | ((uint16_t)p[1]<<8); }
static inline uint32_t proto_rd_u32(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }

// -------------------- CRC16-CCITT (bitwise, small & portable) --------------------
static inline uint16_t proto_crc16_ccitt_ex(const uint8_t* data, uint32_t len, uint16_t crc) {
  while (len--) {
    crc ^= (uint16_t)(*data++) << 8;
    for (int i=0;i<8;i++) crc = (crc & 0x8000) ? (uint16_t)((crc<<1) ^ 0x1021) : (uint16_t)(crc<<1);
  }
  return crc;
}
static inline uint16_t proto_crc16_ccitt(const uint8_t* data, uint32_t len) {
  return proto_crc16_ccitt_ex(data, len, 0xFFFF);
}

// -------------------- KeyId helper (FNV-1a 32-bit) --------------------
static inline uint32_t proto_fnv1a32_ex(const uint8_t* data, uint32_t len, uint32_t h) {
  // FNV-1a: very small, good for cache/version tagging (NOT cryptographic)
  while (len--) {
    h ^= (uint32_t)(*data++);
    h *= 16777619u;
  }
  return h;
}
static inline uint32_t proto_fnv1a32(const uint8_t* data, uint32_t len) {
  return proto_fnv1a32_ex(data, len, 2166136261u);
}

// -------------------- Single-frame Kyber protocol --------------------
#ifndef KPROTO_VER
#define KPROTO_VER 1
#endif

#define KPROTO_MAGIC 0x594B  // 'K''Y' little-endian on wire (0x4B59 as bytes)

// Frame types
typedef enum : uint8_t {
  KPROTO_T_REQ  = 1,  // main -> helper (job request)
  KPROTO_T_RES  = 2,  // helper -> main (job response)
  KPROTO_T_CFG  = 3,  // main -> helper (configuration, usually retained)
  KPROTO_T_NACK = 4   // helper -> main (error / need config)
} kproto_type_t;

// Operation codes (shared across nodes)
typedef enum : uint8_t {
  KOP_B         = 1,     // compute b = A^T * sp
  KOP_V         = 2,     // compute v = t * sp
  KOP_SET_SEED  = 0x10,  // cache seed (rho) for helper1 (and optionally precompute A^T NTT)
  KOP_SET_T     = 0x11   // cache t (pkpv) for helper2
} kproto_op_t;

// NACK codes (payload[0])
typedef enum : uint8_t {
  KERR_OK          = 0,
  KERR_BAD_CRC     = 1,
  KERR_BAD_VER     = 2,
  KERR_BAD_LEN     = 3,
  KERR_NOT_LEASED  = 4,
  KERR_NEED_SEED   = 5,
  KERR_NEED_T      = 6,
  KERR_KEY_MISMATCH= 7,
  KERR_INTERNAL    = 8
} kproto_err_t;

// Fixed header size (bytes)
#define KPROTO_HDR_LEN 18
#define KPROTO_HDR_NOCRC_LEN 16

// A parsed view (payload points into the input buffer)
typedef struct {
  uint8_t  ver;
  uint8_t  type;
  uint8_t  op;
  uint8_t  flags;
  uint32_t job_id;
  uint32_t key_id;
  uint16_t payload_len;
  const uint8_t* payload; // points into the original frame buffer (after header)
} kproto_view_t;

// Build frame into 'out'. Returns total length, or 0 on failure.
static inline uint16_t kproto_build(uint8_t* out, uint16_t out_cap,
                                   uint8_t type, uint8_t op, uint8_t flags,
                                   uint32_t job_id, uint32_t key_id,
                                   const uint8_t* payload, uint16_t payload_len)
{
  const uint32_t total = (uint32_t)KPROTO_HDR_LEN + (uint32_t)payload_len;
  if (!out) return 0;
  if (total > out_cap) return 0;

  // header (no crc yet)
  proto_wr_u16(&out[0], (uint16_t)KPROTO_MAGIC);
  out[2] = (uint8_t)KPROTO_VER;
  out[3] = (uint8_t)type;
  out[4] = (uint8_t)op;
  out[5] = (uint8_t)flags;
  proto_wr_u32(&out[6], job_id);
  proto_wr_u32(&out[10], key_id);
  proto_wr_u16(&out[14], payload_len);

  if (payload_len && payload) {
    memcpy(&out[KPROTO_HDR_LEN], payload, payload_len);
  }

  // crc over header-without-crc + payload
  uint16_t crc = proto_crc16_ccitt(out, KPROTO_HDR_NOCRC_LEN);
  if (payload_len) crc = proto_crc16_ccitt_ex(&out[KPROTO_HDR_LEN], payload_len, crc);
  proto_wr_u16(&out[16], crc);
  return (uint16_t)total;
}

// Parse & validate frame. Returns true if OK.
static inline bool kproto_parse(const uint8_t* in, uint16_t in_len, kproto_view_t* out) {
  if (!in || !out) return false;
  if (in_len < KPROTO_HDR_LEN) return false;

  const uint16_t magic = proto_rd_u16(&in[0]);
  if (magic != (uint16_t)KPROTO_MAGIC) return false;

  const uint8_t ver = in[2];
  if (ver != (uint8_t)KPROTO_VER) return false;

  const uint8_t type = in[3];
  const uint8_t op   = in[4];
  const uint8_t flags= in[5];

  const uint32_t job_id = proto_rd_u32(&in[6]);
  const uint32_t key_id = proto_rd_u32(&in[10]);
  const uint16_t payload_len = proto_rd_u16(&in[14]);

  if ((uint32_t)KPROTO_HDR_LEN + (uint32_t)payload_len != (uint32_t)in_len) return false;

  const uint16_t crc_wire = proto_rd_u16(&in[16]);
  uint16_t crc = proto_crc16_ccitt(in, KPROTO_HDR_NOCRC_LEN);
  if (payload_len) crc = proto_crc16_ccitt_ex(&in[KPROTO_HDR_LEN], payload_len, crc);
  if (crc != crc_wire) return false;

  out->ver = ver;
  out->type = type;
  out->op = op;
  out->flags = flags;
  out->job_id = job_id;
  out->key_id = key_id;
  out->payload_len = payload_len;
  out->payload = &in[KPROTO_HDR_LEN];
  return true;
}
