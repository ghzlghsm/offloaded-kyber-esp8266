#include "indcpa.h"
#include "params.h"
#include "polyvec.h"
#include "symmetric.h"
#include <stdint.h>

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (uniform random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
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

        if (val0 < KYBER_Q) {
            r[ctr++] = (int16_t)val0;
        }
        if (ctr < len && val1 < KYBER_Q) {
            r[ctr++] = (int16_t)val1;
        }
    }

    return ctr;
}

#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

/*************************************************
* Name:        PQCLEAN_MLKEM512_CLEAN_gen_matrix
*
* Description: Deterministically generate matrix A (or A^T) from a seed.
*              Entries are polynomials sampled uniformly mod q via XOF + rejection sampling.
*
* Arguments:   - polyvec *a: output matrix (array of KYBER_K polyvec)
*              - const uint8_t *seed: input seed (KYBER_SYMBYTES bytes)
*              - int transposed: if 1 generate A^T else A
**************************************************/
void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a,
                                       const uint8_t seed[KYBER_SYMBYTES],
                                       int transposed) {
    unsigned int ctr, i, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (i = 0; i < KYBER_K; i++) {
        for (j = 0; j < KYBER_K; j++) {
            if (transposed) {
                xof_absorb(&state, seed, (uint8_t)i, (uint8_t)j);
            } else {
                xof_absorb(&state, seed, (uint8_t)j, (uint8_t)i);
            }

            xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
            buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
            ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

            while (ctr < KYBER_N) {
                xof_squeezeblocks(buf, 1, &state);
                buflen = XOF_BLOCKBYTES;
                ctr += rej_uniform(a[i].vec[j].coeffs + ctr, KYBER_N - ctr, buf, buflen);
            }

            xof_ctx_release(&state);
        }
    }
}
