#include <Arduino.h>
#include <stdint.h>

// optimistic_yield is provided by the ESP8266 Arduino core.
// It yields to background tasks/WiFi and feeds the watchdog if needed.
extern "C" void optimistic_yield(uint32_t interval_us);

extern "C" volatile uint8_t g_load ;

// --- "IoT-like" workload state (kept static for realism and speed) ---
static uint32_t lfsr = 0xACE1u;
static int32_t  filtY_q15 = 0;         // Q15
static const int32_t alpha_q15 = 1638; // ~0.05
static uint32_t crc_state = 0xFFFFFFFFu;
static uint32_t tick = 0;

// A small buffer to create some memory traffic (payload preparation).
static uint8_t buf[128];

// CRC32 step (RAM-safe, no table)
static inline uint32_t crc32_update(uint32_t crc, uint8_t data) {
  crc ^= data;
  for (int i = 0; i < 8; i++) {
    uint32_t mask = -(int32_t)(crc & 1u);
    crc = (crc >> 1) ^ (0xEDB88320u & mask);
  }
  return crc;
}

static inline uint32_t us_to_cycles(uint32_t us) {
  return us * (uint32_t)ESP.getCpuFreqMHz();
}

// One slice budget (microseconds) at 100% load.
// You can tune this to push Kyber latency into tens of ms / ~100ms under 90% load.
#ifndef IOT_SLICE_US_MAX
#define IOT_SLICE_US_MAX 2200u
#endif

static void iot_slice(uint8_t p) {
  if (p == 0) return;

  // budget proportional to p (cap at max)
  uint32_t busy_us = (IOT_SLICE_US_MAX * (uint32_t)p) / 100u;
  if (busy_us > IOT_SLICE_US_MAX) busy_us = IOT_SLICE_US_MAX;

  uint32_t start_cycles = ESP.getCycleCount();
  uint32_t budget_cycles = us_to_cycles(busy_us);

  while ((uint32_t)(ESP.getCycleCount() - start_cycles) < budget_cycles) {
    tick++;

    // 1) fake sensor (LFSR) + simple waveform
    lfsr = (lfsr >> 1) ^ (-(int32_t)(lfsr & 1u) & 0xB400u);
    int16_t noise = (int16_t)(lfsr & 0x3F) - 32;

    static int16_t ramp = -1000;
    ramp += 25;
    if (ramp > 1000) ramp = -1000;

    int16_t x = ramp + noise;

    // 2) IIR filter (Q15): y = y + alpha*(x - y)
    int32_t x_q15 = ((int32_t)x) << 15;
    int32_t err   = x_q15 - filtY_q15;
    filtY_q15     = filtY_q15 + ((err * alpha_q15) >> 15);
    int16_t y     = (int16_t)(filtY_q15 >> 15);

    // 3) pack "payload"
    uint32_t t = tick;
    buf[0] = (uint8_t)(y & 0xFF);
    buf[1] = (uint8_t)((y >> 8) & 0xFF);
    buf[2] = (uint8_t)(t & 0xFF);
    buf[3] = (uint8_t)((t >> 8) & 0xFF);

    // 4) CRC32
    crc_state = crc32_update(crc_state, buf[0]);
    crc_state = crc32_update(crc_state, buf[1]);
    crc_state = crc32_update(crc_state, buf[2]);
    crc_state = crc32_update(crc_state, buf[3]);

    // 5) light mixing (memory traffic)
    for (int i = 4; i < 64; i++) {
      buf[i] ^= (uint8_t)(crc_state >> (i & 7));
    }
  }
}

extern "C" void kyber_coop_point(void) {
  // Run a short chunk of "real" work and then yield to the system/WiFi.
  iot_slice(g_load);
  optimistic_yield(1000); // ~1ms cooperative yield threshold
}
