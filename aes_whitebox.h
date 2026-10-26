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

enum aes_whitebox_status {
  AES_WHITEBOX_OK = 0,
  AES_WHITEBOX_INVALID_LENGTH = -1,
  AES_WHITEBOX_INVALID_ARGUMENT = -2,
  AES_WHITEBOX_INSUFFICIENT_CAPACITY = -3
};

// CBC encryption without padding: len must be a multiple of 16 and c must
// hold at least len bytes. Exact in-place use is supported; other overlap is
// unsupported. iv must not overlap c and is not modified. Each call restarts
// from iv, which must be unpredictable for each message. No authentication is
// provided. Invalid length/null arguments return an error before writing c.
// len == 0 succeeds without accessing any pointer (NULL pointers are allowed).
int aes_whitebox_encrypt_cbc(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);

// CBC with PKCS#7: always adds 1..16 bytes, including a full block for len == 0
// or block-aligned input. Returns the status codes above; overflow is INVALID_LENGTH.
// iv, c and written must be non-null; m may be null only for empty input.
// capacity must cover len + (16 - len % 16). On success, *written is that size;
// on failure, c and *written are unchanged. Exact in-place use requires padded
// capacity; other overlap is unsupported. written must not overlap any buffer,
// and iv must not overlap c. The CBC IV/authentication rules above also apply.
int aes_whitebox_encrypt_cbc_pkcs7(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c, size_t capacity, size_t* written);

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
