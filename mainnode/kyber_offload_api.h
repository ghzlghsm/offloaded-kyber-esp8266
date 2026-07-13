#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void kyber_offload_poll(void);

int kyber_offload_request_b(const uint8_t seed32[32], const uint8_t *sp_raw, uint32_t *job_id);
int kyber_offload_request_v(const uint8_t pkpv_bytes[KYBER_POLYVECBYTES], const uint8_t *sp_raw, uint32_t *job_id);


int kyber_offload_wait_b(uint32_t job_id, uint8_t *b_out);
int kyber_offload_wait_v(uint32_t job_id, uint8_t *v_out);

#ifdef __cplusplus
}
#endif
