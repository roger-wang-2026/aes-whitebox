// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AES_WHITEBOX_H_
#define AES_WHITEBOX_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

// Core accepts externally encoded input and returns externally encoded output.
// Adapters are generated separately and must match the exact core tables.
void aes_whitebox_encrypt_encoded_block(const uint8_t in[16], uint8_t out[16]);
void aes_whitebox_encode_input_block(const uint8_t in[16], uint8_t out[16]);
void aes_whitebox_decode_output_block(const uint8_t in[16], uint8_t out[16]);

// Mode functions accept ordinary bytes. Exact in-place use is supported;
// other input/output overlap is not supported. Each call starts from its IV.
void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);

void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m,
    size_t len, uint8_t* c);
void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c,
    size_t len, uint8_t* m);

#ifdef __cplusplus
}
#endif

#endif  // AES_WHITEBOX_H_
