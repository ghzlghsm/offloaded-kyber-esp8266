#ifndef PQCLEAN_MLKEM512_CLEAN_INDCPA_H
#define PQCLEAN_MLKEM512_CLEAN_INDCPA_H

#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a,
                                       const uint8_t seed[KYBER_SYMBYTES],
                                       int transposed);

void PQCLEAN_MLKEM512_CLEAN_indcpa_keypair_derand(
        uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]);

// جدید: return code (0=OK, nonzero=FAIL)
int PQCLEAN_MLKEM512_CLEAN_indcpa_enc_ex(uint8_t *c,
                                        const uint8_t *m,
                                        const uint8_t *pk,
                                        const uint8_t *coins);

// سازگاری با PQClean (همان void)
void PQCLEAN_MLKEM512_CLEAN_indcpa_enc(uint8_t *c,
                                      const uint8_t *m,
                                      const uint8_t *pk,
                                      const uint8_t *coins);

void PQCLEAN_MLKEM512_CLEAN_indcpa_dec(uint8_t *m,
                                      const uint8_t *c,
                                      const uint8_t *sk);

#endif
