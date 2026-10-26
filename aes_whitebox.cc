// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "aes_whitebox.h"

#include <aes_whitebox_tables.cc>

namespace {

void ShiftRows(uint8_t state[16]) {
  constexpr int shifts[16] = {
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11,
  };

  const uint8_t in[16] = {
    state[ 0], state[ 1], state[ 2], state[ 3],
    state[ 4], state[ 5], state[ 6], state[ 7],
    state[ 8], state[ 9], state[10], state[11],
    state[12], state[13], state[14], state[15],
  };

  for (int i = 0; i < 16; i++)
    state[i] = in[shifts[i]];
}

void ApplyStage(uint8_t state[16], const uint32_t tables[16][256],
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

void Cipher(uint8_t state[16]) {
  for (int r = 0; r < Nr-1; ++r) {
    ShiftRows(state);
    ApplyStage(state, Tyboxes[r], XorTy[r]);
    ApplyStage(state, MBL[r], XorMBL[r]);
  }
  ShiftRows(state);
  for (int i = 0; i < 16; ++i) state[i] = TboxesLast[i][state[i]];
}

#ifndef AES_WHITEBOX_CORE_ONLY
void PlainCipher(uint8_t state[16]) {
  aes_whitebox_encode_input_block(state, state);
  Cipher(state);
  aes_whitebox_decode_output_block(state, state);
}
#endif

}  // namespace

extern "C" {

void aes_whitebox_encrypt_encoded_block(const uint8_t in[16], uint8_t out[16]) {
  for (int i = 0; i < 16; ++i) out[i] = in[i];
  Cipher(out);
}

#ifndef AES_WHITEBOX_CORE_ONLY

int aes_whitebox_encrypt_cbc(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  if (len % 16 != 0)
    return AES_WHITEBOX_INVALID_LENGTH;
  if (len == 0)
    return AES_WHITEBOX_OK;
  if (!iv || !m || !c)
    return AES_WHITEBOX_INVALID_ARGUMENT;

  uint8_t feedback[16];
  for (int j = 0; j < 16; ++j)
    feedback[j] = iv[j];

  for (size_t offset = 0; offset < len; offset += 16) {
    for (int j = 0; j < 16; ++j)
      feedback[j] ^= m[offset + j];
    PlainCipher(feedback);
    for (int j = 0; j < 16; ++j)
      c[offset + j] = feedback[j];
  }
  return AES_WHITEBOX_OK;
}

int aes_whitebox_encrypt_cbc_pkcs7(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c, size_t capacity, size_t* written) {
  const uint8_t padding = 16 - len % 16;
  if (len > SIZE_MAX - padding)
    return AES_WHITEBOX_INVALID_LENGTH;
  if (!iv || !c || !written || (len != 0 && !m))
    return AES_WHITEBOX_INVALID_ARGUMENT;
  const size_t required = len + padding;
  if (capacity < required)
    return AES_WHITEBOX_INSUFFICIENT_CAPACITY;

  const size_t full = len - len % 16;
  // All preconditions of the unpadded API have already been checked.
  aes_whitebox_encrypt_cbc(iv, m, full, c);
  const uint8_t* feedback = full == 0 ? iv : c + full - 16;
  uint8_t last[16];
  for (size_t j = 0; j < 16; ++j)
    last[j] = (j < len % 16 ? m[full + j] : padding) ^ feedback[j];
  PlainCipher(last);
  for (size_t j = 0; j < 16; ++j)
    c[full + j] = last[j];
  *written = required;
  return AES_WHITEBOX_OK;
}

void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      PlainCipher(cfb_blk);
    cfb_blk[i & 0xf] ^= m[i];
    c[i] = cfb_blk[i & 0xf];
  }
}

void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      PlainCipher(cfb_blk);
    uint8_t t = c[i];
    m[i] = cfb_blk[i & 0xf] ^ t;
    cfb_blk[i & 0xf] = t;
  }
}

void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t cfb_blk[16];

  for (int i = 0; i < 16; i++)
    cfb_blk[i] = iv[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0)
      PlainCipher(cfb_blk);
    c[i] = m[i] ^ cfb_blk[i & 0xf];
  }
}

void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  aes_whitebox_encrypt_ofb(iv, c, len, m);
}

void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m,
    size_t len, uint8_t* c) {
  uint8_t counter[16], buf[16];

  for (int i = 0; i < 16; i++)
    counter[i] = nonce[i];

  for (size_t i = 0; i < len; i++) {
    if ((i & 0xf) == 0) {
      for (int j = 0; j < 16; j++)
        buf[j] = counter[j];
      PlainCipher(buf);
      for (int j = 15; j >= 0; j--) {
        counter[j]++;
        if (counter[j])
          break;
      }
    }
    c[i] = m[i] ^ buf[i & 0xf];
  }
}

void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c,
    size_t len, uint8_t* m) {
  aes_whitebox_encrypt_ctr(nonce, c, len, m);
}

#endif  // AES_WHITEBOX_CORE_ONLY

}  // extern "C"
