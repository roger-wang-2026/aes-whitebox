// Inverse white-box AES runtime. Link only when decryption is required.
#include "aes_whitebox.h"
#include "aes_whitebox_internal.h"

#include <aes_whitebox_decrypt_tables.cc>

namespace {

void InvShiftRows(uint8_t state[16]) {
  constexpr int rows[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3
  };
  uint8_t copy[16];
  for (int i = 0; i < 16; ++i) copy[i] = state[i];
  for (int i = 0; i < 16; ++i) state[i] = copy[rows[i]];
}

void InverseCipher(uint8_t state[16]) {
  for (int r = 0; r < Nr-1; ++r) {
    InvShiftRows(state);
    aes_whitebox_internal::ApplyStage(state, Tyboxes[r], XorTy[r]);
    aes_whitebox_internal::ApplyStage(state, MBL[r], XorMBL[r]);
  }
  InvShiftRows(state);
  for (int i = 0; i < 16; ++i) state[i] = TboxesLast[i][state[i]];
}

#ifndef AES_WHITEBOX_CORE_ONLY
void PlainInverseCipher(uint8_t state[16]) {
  aes_whitebox_decrypt_encode_input_block(state, state);
  InverseCipher(state);
  aes_whitebox_decrypt_decode_output_block(state, state);
}
#endif

}  // namespace

extern "C" {

void aes_whitebox_decrypt_encoded_block(const uint8_t in[16], uint8_t out[16]) {
  for (int i = 0; i < 16; ++i) out[i] = in[i];
  InverseCipher(out);
}

#ifndef AES_WHITEBOX_CORE_ONLY
int aes_whitebox_decrypt_cbc(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  if (len % 16 != 0) return AES_WHITEBOX_INVALID_LENGTH;
  if (len == 0) return AES_WHITEBOX_OK;
  if (!iv || !c || !m) return AES_WHITEBOX_INVALID_ARGUMENT;

  uint8_t feedback[16], current[16], block[16];
  for (int j = 0; j < 16; ++j) feedback[j] = iv[j];
  for (size_t offset = 0; offset < len; offset += 16) {
    // Preserve ciphertext before writing plaintext, including in-place calls.
    for (int j = 0; j < 16; ++j) current[j] = block[j] = c[offset+j];
    PlainInverseCipher(block);
    for (int j = 0; j < 16; ++j) {
      m[offset+j] = block[j] ^ feedback[j];
      feedback[j] = current[j];
    }
  }
  return AES_WHITEBOX_OK;
}

int aes_whitebox_decrypt_cbc_pkcs7(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m, size_t capacity, size_t* written) {
  if (len == 0 || len % 16 != 0) return AES_WHITEBOX_INVALID_LENGTH;
  if (!iv || !c || !m || !written) return AES_WHITEBOX_INVALID_ARGUMENT;

  const size_t prefix = len - 16;
  const uint8_t* feedback = prefix == 0 ? iv : c + prefix - 16;
  uint8_t last[16];
  for (size_t j = 0; j < 16; ++j) last[j] = c[prefix+j];
  PlainInverseCipher(last);
  for (size_t j = 0; j < 16; ++j) last[j] ^= feedback[j];

  const uint8_t padding = last[15];
  unsigned invalid = (padding == 0) | (padding > 16);
  // Always read all sixteen bytes; never index using an unchecked pad length.
  for (unsigned j = 0; j < 16; ++j) {
    unsigned mask = 0u - static_cast<unsigned>(j < padding);
    invalid |= mask & static_cast<unsigned>(last[15-j] ^ padding);
  }
  if (invalid) return AES_WHITEBOX_INVALID_PADDING;
  const size_t required = len - padding;
  if (capacity < required) return AES_WHITEBOX_INSUFFICIENT_CAPACITY;

  // Validation is complete. Cache the final plaintext before in-place prefix
  // decryption can overwrite its ciphertext feedback block.
  aes_whitebox_decrypt_cbc(iv, c, prefix, m);
  const size_t tail = 16 - padding;
  for (size_t j = 0; j < tail; ++j) m[prefix+j] = last[j];
  *written = required;
  return AES_WHITEBOX_OK;
}
#endif

}  // extern "C"
