#include <Arduino.h>
#include <stdarg.h>
#include <stdio.h>

extern "C" void dbg_printf(const char* fmt, ...) {
  char buf[256];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  Serial.print(buf);   // یا Serial.printf("%s", buf);
}
extern "C" uint32_t prof_us(void) { return (uint32_t)micros(); }

extern "C" void prof_print(const char* tag, uint32_t dt_us) {
  Serial.printf("[PROF] %s %lu us\n", tag, (unsigned long)dt_us);
}
