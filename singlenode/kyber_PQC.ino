#include <Arduino.h>
#include <stdint.h>

extern "C" {
  #include "api.h"
  #include "coop.h"
}

/*
 * Kyber (ML-KEM-512) – Standalone execution on ESP8266 (single node)
 *
 * Thesis mode:
 *  - Heavy "IoT-like" workload is executed cooperatively from inside Kyber via checkpoints.
 *  - Kyber is made cooperative by inserting KYBER_COOP(...) in hot loops (NTT/polyvec/sampling/hash/...).
 *  - Load level (g_load) controls how much IoT work is done per checkpoint (0..90%).
 *
 * Benchmark:
 *  - Load sweep: 0,20,30,40,50,60,70,80,90 (%)
 *  - N = 10 runs each load
 *  - Print each run + per-load summary (avg/min/max)
 */

static uint8_t pk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES];
static uint8_t ct[PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss1[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];
static uint8_t ss2[PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES];

extern "C" { volatile uint8_t g_load = 0; }

static bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++) if (a[i] != b[i]) return false;
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(300);

  // time to open serial monitor
  delay(900);

  Serial.println("=== ML-KEM-512 (PQClean) – Cooperative Kyber + IoT load (single node) ===");
  Serial.printf("Sizes: pk=%d sk=%d ct=%d ss=%d\n",
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES,
                PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);
  Serial.println("PRNG: deterministic ChaCha20 (test/benchmark)");
  Serial.printf("KYBER_COOP_STRIDE=%u (power-of-two)\n", (unsigned)KYBER_COOP_STRIDE);
  Serial.println("NOTE: Reset after completion is acceptable.");
}

void loop() {
  static const uint8_t loads[] = {0, 10, 20, 30, 40, 50, 60, 70, 80, 90};
  static uint8_t idx = 0;

  const int N = 100;

  if (idx >= sizeof(loads)) {
    g_load = 0;
    Serial.println("\n[DONE] All loads tested.");
    delay(2000);
    return;
  }

  uint8_t p = loads[idx++];
  g_load = p;
  Serial.printf("\n==============================\n");
  Serial.printf("Coop IoT load = %u%% | N = %d\n", p, N);
  Serial.printf("==============================\n");
  Serial.printf("contStack=%u heap=%u\n", ESP.getFreeContStack(), ESP.getFreeHeap());

  // settle a bit
  delay(200);

  unsigned long sum_k = 0, sum_e = 0, sum_d = 0;
  unsigned long min_k = 0xFFFFFFFFUL, min_e = 0xFFFFFFFFUL, min_d = 0xFFFFFFFFUL;
  unsigned long max_k = 0, max_e = 0, max_d = 0;

  for (int i = 0; i < N; i++) {
    uint32_t t0, t1;

    t0 = micros();
    int r1 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    t1 = micros();
    unsigned long tk = (unsigned long)(t1 - t0);

    t0 = micros();
    int r2 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss1, pk);
    t1 = micros();
    unsigned long te = (unsigned long)(t1 - t0);
    Serial.printf("coop_hits=%lu\n", (unsigned long)g_coop_hits);
    g_coop_hits = 0;

    t0 = micros();
    int r3 = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
    t1 = micros();
    unsigned long td = (unsigned long)(t1 - t0);
    Serial.printf("coop_hits=%lu\n", (unsigned long)g_coop_hits);
    g_coop_hits = 0;

    bool ok = (r1 == 0 && r2 == 0 && r3 == 0) &&
              bytes_equal(ss1, ss2, PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES);

    Serial.printf("#%03d  keypair=%lu us | enc=%lu us | dec=%lu us | %s\n",
                  i + 1, tk, te, td, ok ? "OK" : "FAIL");

    sum_k += tk; sum_e += te; sum_d += td;

    if (tk < min_k) min_k = tk;
    if (te < min_e) min_e = te;
    if (td < min_d) min_d = td;

    if (tk > max_k) max_k = tk;
    if (te > max_e) max_e = te;
    if (td > max_d) max_d = td;

    // Feed WDT between runs (extra safety)
    delay(0);
  }

  Serial.println("\n--- Summary ---");
  Serial.printf("keypair: avg=%.2f us | min=%lu | max=%lu\n",
                (double)sum_k / N, min_k, max_k);
  Serial.printf("encaps : avg=%.2f us | min=%lu | max=%lu\n",
                (double)sum_e / N, min_e, max_e);
  Serial.printf("decaps : avg=%.2f us | min=%lu | max=%lu\n",
                (double)sum_d / N, min_d, max_d);

  // A short pause between load levels
  delay(1200);
}
