#include "indcpa.h"
#include "ntt.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "randombytes.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "kyber_offload_api.h"
#include "coop.h"

#if defined(ARDUINO)
  #include <Arduino.h>
#endif

#if defined(ARDUINO_ARCH_ESP8266)
void optimistic_yield(uint32_t interval_us);
#endif

#ifdef __cplusplus
extern "C" {
#endif
void dbg_printf(const char* fmt, ...);
#ifdef __cplusplus
}
#endif
// ---- sp packing: 3-bit per coefficient (assumes KYBER_ETA1 <= 3) ----
#define SP_BITS 3u
#if (KYBER_ETA1 > 3)
#error "sp packing assumes KYBER_ETA1 <= 3"
#endif
#define SP_COEFFS      ((uint32_t)KYBER_K * (uint32_t)KYBER_N)
#define SP_PACKED_BYTES ((SP_COEFFS * SP_BITS) / 8u)   // for K=2,N=256 => 192

// ---------------------------------------------
// ===== FIX #1: move big locals off stack =====
static polyvec g_pkpv , g_skpv;
static uint8_t g_seed[KYBER_SYMBYTES];

static polyvec g_sp, g_ep, g_b;
static poly g_v, g_epp, g_k;
static poly g_mp;

static uint8_t g_sp_raw[SP_PACKED_BYTES];
static uint8_t g_b_bytes[KYBER_POLYVECBYTES];
static uint8_t g_v_bytes[KYBER_POLYBYTES];

// =============================
// pack sp as 3-bit values (v = coeff + KYBER_ETA1) packed LSB-first, 8 coeffs -> 3 bytes
static void pack_sp_raw(uint8_t out[], const polyvec *sp) {
  uint32_t out_i = 0;

  for (int j = 0; j < KYBER_K; j++) {
    for (int i = 0; i < KYBER_N; i += 8) {
      uint32_t w = 0;

      // pack 8 coeffs -> 24 bits
      for (int k = 0; k < 8; k++) {
        int16_t c = sp->vec[j].coeffs[i + k];
        int32_t v = (int32_t)c + (int32_t)KYBER_ETA1;

        // clamp just in case (shouldn't happen for eta1 noise)
        if (v < 0) v = 0;
        if (v > (int32_t)(2 * KYBER_ETA1)) v = (int32_t)(2 * KYBER_ETA1);

        w |= ((uint32_t)(v & 0x7)) << (3 * k);
      }

      out[out_i + 0] = (uint8_t)(w & 0xFF);
      out[out_i + 1] = (uint8_t)((w >> 8) & 0xFF);
      out[out_i + 2] = (uint8_t)((w >> 16) & 0xFF);
      out_i += 3;

      if ((i & 63) == 0) kyber_offload_poll();
    }
    kyber_offload_poll();
  }
}
/*************************************************
* pack/unpack helpers (PQClean)
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, pk);
  memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES]) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(sk, packedsk);
}

static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_compress(r, b);
  PQCLEAN_MLKEM512_CLEAN_poly_compress(r + KYBER_POLYVECCOMPRESSEDBYTES, v);
}

static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES]) {
  PQCLEAN_MLKEM512_CLEAN_polyvec_decompress(b, c);
  PQCLEAN_MLKEM512_CLEAN_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/*************************************************
* rej_uniform / gen_matrix  (poll added)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while (ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
    val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
    pos += 3;

    if (val0 < KYBER_Q) r[ctr++] = val0;
    if (ctr < len && val1 < KYBER_Q) r[ctr++] = val1;

    if ((pos & 63) == 0) kyber_offload_poll();
  }
  return ctr;
}

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

// IMPORTANT: move this buffer off stack
static uint8_t g_gen_buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];

void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a,
                                       const uint8_t seed[KYBER_SYMBYTES],
                                       int transposed) {
  unsigned int ctr, i, j;
  unsigned int buflen;
  uint8_t *buf = g_gen_buf;
  xof_state state;

  for (i = 0; i < KYBER_K; i++) {
    KYBER_COOP(i);
    for (j = 0; j < KYBER_K; j++) {
      KYBER_COOP(j);
      if (transposed) xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
      else            xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);

      kyber_offload_poll();

      xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
      buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
      ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

      kyber_offload_poll();

      while (ctr < KYBER_N) {
        xof_squeezeblocks(buf, 1, &state);
        buflen = XOF_BLOCKBYTES;
        ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
        kyber_offload_poll();
      }
      xof_ctx_release(&state);
      kyber_offload_poll();
    }
  }
}

/*************************************************
* keypair_derand (STACK-SAFE)
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                                                  uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                                                  const uint8_t coins[KYBER_SYMBYTES]) {
  unsigned int i;
  uint8_t buf2[2 * KYBER_SYMBYTES];
  const uint8_t *publicseed = buf2;
  const uint8_t *noiseseed = buf2 + KYBER_SYMBYTES;
  uint8_t nonce = 0;
  polyvec a[KYBER_K], e, pkpv, skpv;  

  memcpy(buf2, coins, KYBER_SYMBYTES);
  buf2[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf2, buf2, KYBER_SYMBYTES + 1);

  kyber_offload_poll();

  // use global matrix
  PQCLEAN_MLKEM512_CLEAN_gen_matrix(a, publicseed, 0);

  for (i = 0; i < KYBER_K; i++) {
    KYBER_COOP(i);
    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    kyber_offload_poll();
  }
  for (i = 0; i < KYBER_K; i++) {
    KYBER_COOP(i);
    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    kyber_offload_poll();
  }

  PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&skpv);
  kyber_offload_poll();
  PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(&e);
  kyber_offload_poll();

  for (i = 0; i < KYBER_K; i++) {
    KYBER_COOP(i);
    PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    PQCLEAN_MLKEM512_CLEAN_poly_tomont(&pkpv.vec[i]);
    kyber_offload_poll();
  }

  PQCLEAN_MLKEM512_CLEAN_polyvec_add(&pkpv, &pkpv, &e);
  PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* indcpa_enc_ex (OFFLOAD)
**************************************************/
int PQCLEAN_MLKEM512_CLEAN_indcpa_enc_ex(uint8_t *c,
                                        const uint8_t *m,
                                        const uint8_t *pk,
                                        const uint8_t *coins) {
  //polyvec *pkpv = &g_pkpv;
  //uint8_t *seed = g_seed;

  polyvec *sp = &g_sp;
  polyvec *ep = &g_ep;
  polyvec *b  = &g_b;

  poly *v   = &g_v;
  poly *epp = &g_epp;
  poly *k   = &g_k;

  //unpack_pk(pkpv, seed, pk);
  const uint8_t* seed = pk + KYBER_POLYVECBYTES;
  const uint8_t* pkpv_bytes = pk;

  unsigned int nonce = 0;
  for (int i = 0; i < KYBER_K; i++) {
    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta1(&sp->vec[i], coins, nonce++);
    kyber_offload_poll();
  #if defined(ARDUINO)
    delay(0);
  #endif
  }
  delay(0);
  pack_sp_raw(g_sp_raw, sp);

  uint32_t job_b = 0, job_v = 0;
  
  int off_b = kyber_offload_request_b(seed, g_sp_raw, &job_b);
  int off_v = kyber_offload_request_v(pkpv_bytes, g_sp_raw, &job_v);

  delay(0);
  //dbg_printf("off_b=%d job_b=%lu | off_v=%d job_v=%lu\n",off_b, (unsigned long)job_b,off_v, (unsigned long)job_v);

  #if defined(ARDUINO)
    delay(0);
  #endif

  for (int i = 0; i < KYBER_K; i++) {
    PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(&ep->vec[i], coins, nonce++);
    kyber_offload_poll();
    #if defined(ARDUINO)
      delay(0);
    #endif
  }
  PQCLEAN_MLKEM512_CLEAN_poly_getnoise_eta2(epp, coins, nonce++);
  kyber_offload_poll();
  #if defined(ARDUINO)
    delay(0);
  #endif

  PQCLEAN_MLKEM512_CLEAN_poly_frommsg(k, m);
  kyber_offload_poll();
  
 // اگر offload شروع نشد => FAIL
  if (off_b != 0 || off_v != 0) {
    memset(c, 0, KYBER_INDCPA_BYTES);
    return -1;
  }
  //dbg_printf("[INDCPA] wait job_b=%lu job_v=%lu\n",(unsigned long)job_b, (unsigned long)job_v);
// اگر جواب‌ها نرسید => FAIL
  if (kyber_offload_wait_b(job_b, g_b_bytes) != 0 ||
      kyber_offload_wait_v(job_v, g_v_bytes) != 0) {
    memset(c, 0, KYBER_INDCPA_BYTES);
    return -1;
  }

  PQCLEAN_MLKEM512_CLEAN_polyvec_frombytes(b, g_b_bytes);
  PQCLEAN_MLKEM512_CLEAN_poly_frombytes(v, g_v_bytes);

  PQCLEAN_MLKEM512_CLEAN_polyvec_add(b, b, ep);
  PQCLEAN_MLKEM512_CLEAN_polyvec_reduce(b);

  PQCLEAN_MLKEM512_CLEAN_poly_add(v, v, epp);
  PQCLEAN_MLKEM512_CLEAN_poly_add(v, v, k);
  PQCLEAN_MLKEM512_CLEAN_poly_reduce(v);

  pack_ciphertext(c, b, v);
  return 0;
}

void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t *c,
                                      const uint8_t *m,
                                      const uint8_t *pk,
                                      const uint8_t *coins) {
  (void)PQCLEAN_MLKEM512_CLEAN_indcpa_enc_ex(c, m, pk, coins);
}

/*************************************************
* indcpa_dec (STACK-SAFE)
**************************************************/

void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                                       const uint8_t c[KYBER_INDCPA_BYTES],
                                       const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {


  polyvec *b    = &g_b;       // استفاده از global
  poly    *v    = &g_v;       // استفاده از global
  polyvec *skpv = &g_skpv;    // استفاده از global
  poly    *mp   = &g_mp;      // جدا

  unpack_ciphertext(b, v, c);
  unpack_sk(skpv, sk);

  PQCLEAN_MLKEM512_CLEAN_polyvec_ntt(b);
  kyber_offload_poll();

  PQCLEAN_MLKEM512_CLEAN_polyvec_basemul_acc_montgomery(mp, skpv, b);
  kyber_offload_poll();

  PQCLEAN_MLKEM512_CLEAN_poly_invntt_tomont(mp);
  kyber_offload_poll();

  PQCLEAN_MLKEM512_CLEAN_poly_sub(mp, v, mp);
  PQCLEAN_MLKEM512_CLEAN_poly_reduce(mp);

  PQCLEAN_MLKEM512_CLEAN_poly_tomsg(m, mp);
}

