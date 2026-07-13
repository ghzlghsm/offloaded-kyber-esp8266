#ifndef PQCLEAN_MLKEM512_CLEAN_INDCPA_H
#define PQCLEAN_MLKEM512_CLEAN_INDCPA_H

#include "params.h"
#include "polyvec.h"
#include <stdint.h>

// فقط چیزی که helper1 لازم دارد
void PQCLEAN_MLKEM512_CLEAN_gen_matrix(polyvec *a,
                                       const uint8_t seed[KYBER_SYMBYTES],
                                       int transposed);

#endif
