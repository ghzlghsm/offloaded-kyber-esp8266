#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void randombytes(uint8_t *out, size_t outlen);

/* اختیاری: برای اینکه بتونی seed پروژه را عوض کنی */
void randombytes_seed(const uint8_t seed32[32], const uint8_t nonce12[12]);

#ifdef __cplusplus
}
#endif

#endif
