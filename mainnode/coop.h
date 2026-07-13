#ifndef KYBER_COOP_H
#define KYBER_COOP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// 0..90 (%). Set from the Arduino sketch.
extern volatile uint8_t g_load;

// Called at Kyber checkpoints.
// It will (1) run a short "IoT-like" workload slice proportional to g_load,
// and (2) yield to the ESP8266 background/WiFi + feed WDT (via optimistic_yield).
void kyber_coop_point(void);

#ifdef __cplusplus
} // extern "C"
#endif

// -------- Checkpoint policy --------
// Power-of-two stride is fastest (bitmask).
#ifndef KYBER_COOP_STRIDE
#define KYBER_COOP_STRIDE 128u
#endif

// Call this in hot loops: KYBER_COOP(i);
#define KYBER_COOP(i) do { \
  if ((((uint32_t)(i)) & (KYBER_COOP_STRIDE - 1u)) == 0u) { \
    kyber_coop_point(); \
  } \
} while (0)

#endif // KYBER_COOP_H
