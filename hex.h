#ifndef AES_WHITEBOX_HEX_H_
#define AES_WHITEBOX_HEX_H_
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline int hex_digit(unsigned char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static inline int parse_hex(const char* text, uint8_t* out, size_t size) {
  size_t length = strlen(text);
  if (length / 2 != size || length % 2) return 0;
  for (size_t i = 0; i < size; ++i) {
    int high = hex_digit((unsigned char)text[2*i]);
    int low = hex_digit((unsigned char)text[2*i+1]);
    if (high < 0 || low < 0) return 0;
    out[i] = (uint8_t)((high << 4) | low);
  }
  return 1;
}
#endif
