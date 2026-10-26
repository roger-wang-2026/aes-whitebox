#ifndef AES_WHITEBOX_INTERNAL_H_
#define AES_WHITEBOX_INTERNAL_H_
#include <stdint.h>

namespace aes_whitebox_internal {
inline void ApplyStage(uint8_t state[16], const uint32_t tables[16][256],
                const uint8_t xors[96][16][16]) {
  for (int col = 0; col < 4; ++col) {
    uint32_t words[4];
    for (int lane = 0; lane < 4; ++lane)
      words[lane] = tables[col*4+lane][state[col*4+lane]];
    for (int byte = 0; byte < 4; ++byte) {
      uint8_t value = 0;
      for (int half = 0; half < 2; ++half) {
        int shift = 28 - byte*8 - half*4;
        int base = col*24 + byte*6;
        uint8_t left = xors[base+half*2][(words[0] >> shift) & 15][(words[1] >> shift) & 15];
        uint8_t right = xors[base+half*2+1][(words[2] >> shift) & 15][(words[3] >> shift) & 15];
        value |= xors[base+4+half][left][right] << (half == 0 ? 4 : 0);
      }
      state[col*4+byte] = value;
    }
  }
}

}  // namespace aes_whitebox_internal
#endif
