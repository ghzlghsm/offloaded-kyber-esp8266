#include "randombytes.h"
#include <string.h>

/*
 * Deterministic ChaCha20 PRNG (C-only)
 * - Good for reproducible benchmarking and distributed/offload debugging
 * - NOT a true entropy source
 *
 * You can keep fixed seed/nonce for all nodes => same randomness everywhere
 * Or set per-node nonce for different streams.
 */

static uint32_t st[16];
static int initialized = 0;

static uint32_t rotl32(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

static uint32_t load32_le(const uint8_t *p) {
  return ((uint32_t)p[0]) |
         ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t x) {
  p[0] = (uint8_t)(x);
  p[1] = (uint8_t)(x >> 8);
  p[2] = (uint8_t)(x >> 16);
  p[3] = (uint8_t)(x >> 24);
}

#define QR(a,b,c,d)         \
  do {                      \
    a += b; d ^= a; d = rotl32(d,16); \
    c += d; b ^= c; b = rotl32(b,12); \
    a += b; d ^= a; d = rotl32(d, 8); \
    c += d; b ^= c; b = rotl32(b, 7); \
  } while (0)

static void chacha20_block(uint8_t out[64], const uint32_t in[16]) {
  uint32_t x[16];
  memcpy(x, in, 64);

  for (int i = 0; i < 10; i++) { // 20 rounds
    // column rounds
    QR(x[0], x[4], x[8],  x[12]);
    QR(x[1], x[5], x[9],  x[13]);
    QR(x[2], x[6], x[10], x[14]);
    QR(x[3], x[7], x[11], x[15]);
    // diagonal rounds
    QR(x[0], x[5], x[10], x[15]);
    QR(x[1], x[6], x[11], x[12]);
    QR(x[2], x[7], x[8],  x[13]);
    QR(x[3], x[4], x[9],  x[14]);
  }

  for (int i = 0; i < 16; i++) {
    x[i] += in[i];
    store32_le(out + 4*i, x[i]);
  }
}

void randombytes_seed(const uint8_t seed32[32], const uint8_t nonce12[12]) {
  // constants "expand 32-byte k"
  st[0] = 0x61707865;
  st[1] = 0x3320646e;
  st[2] = 0x79622d32;
  st[3] = 0x6b206574;

  // key (32 bytes)
  for (int i = 0; i < 8; i++) {
    st[4 + i] = load32_le(seed32 + 4*i);
  }

  // counter
  st[12] = 0;

  // nonce (12 bytes)
  st[13] = load32_le(nonce12 + 0);
  st[14] = load32_le(nonce12 + 4);
  st[15] = load32_le(nonce12 + 8);

  initialized = 1;
}

// یک seed/nonce پیش‌فرض ثابت (واحد برای همه)
static void init_default(void) {
  // 32-byte seed ثابت
  static const uint8_t seed32[32] = {
    0x00,0x01,0x02,0x03, 0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
    0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,
    0x18,0x19,0x1A,0x1B, 0x1C,0x1D,0x1E,0x1F
  };

  // 12-byte nonce ثابت
  static const uint8_t nonce12[12] = {
    0xAA,0xBB,0xCC,0xDD, 0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88
  };

  randombytes_seed(seed32, nonce12);
}

void randombytes(uint8_t *out, size_t outlen) {
  if (!initialized) init_default();

  uint8_t block[64];
  size_t pos = 0;

  while (outlen > 0) {
    chacha20_block(block, st);
    st[12]++; // counter++

    size_t n = (outlen < 64) ? outlen : 64;
    memcpy(out + pos, block, n);

    pos += n;
    outlen -= n;
  }
}
