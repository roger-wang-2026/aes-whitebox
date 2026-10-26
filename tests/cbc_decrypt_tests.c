// NIST SP 800-38A CBC decryption prefixes and inverse-core boundaries.
#include <stdio.h>
#include <string.h>
#include "aes_whitebox.h"
#include "aunit.h"
#include "hex.h"

static int guard(const uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; ++i) if (data[i] != 0xa5) return 0;
  return 1;
}

au_main
{
  uint8_t plain[64], iv[16], cipher[64], saved_iv[16], saved_cipher[64];
  if (argc != 4 || !parse_hex(argv[1], plain, sizeof(plain)) ||
      !parse_hex(argv[2], iv, sizeof(iv)) || !parse_hex(argv[3], cipher, sizeof(cipher))) {
    fputs("expected plaintext, IV and CBC ciphertext in hex\n", stderr);
    return 1;
  }
  memcpy(saved_iv, iv, sizeof(iv));
  memcpy(saved_cipher, cipher, sizeof(cipher));
  uint8_t encoded[16], decoded[16], expected_block[16];
  for (int i = 0; i < 16; ++i) expected_block[i] = plain[i] ^ iv[i];
  aes_whitebox_decrypt_encode_input_block(cipher, encoded);
  aes_whitebox_decrypt_encoded_block(encoded, decoded);
  aes_whitebox_decrypt_decode_output_block(decoded, decoded);
  au_eq("Inverse encoded block vector", memcmp(decoded, expected_block, 16), 0);
  aes_whitebox_decrypt_encode_input_block(cipher, encoded);
  aes_whitebox_decrypt_encoded_block(encoded, encoded);
  aes_whitebox_decrypt_decode_output_block(encoded, encoded);
  au_eq("Inverse encoded block in-place", memcmp(encoded, expected_block, 16), 0);

  uint8_t storage[66], snapshot[66];
  const size_t lengths[] = {0, 16, 32, 48, 64};
  for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
    size_t len = lengths[i];
    for (int in_place = 0; in_place < 2; ++in_place) {
      memset(storage, 0xa5, sizeof(storage));
      if (in_place) memcpy(storage+1, cipher, len);
      int result = aes_whitebox_decrypt_cbc(iv, in_place ? storage+1 : cipher, len, storage+1);
      au_eq("CBC decrypt success", result, AES_WHITEBOX_OK);
      au_eq("CBC decrypt NIST prefix", memcmp(storage+1, plain, len), 0);
      au_eq("CBC decrypt leading guard", storage[0], 0xa5);
      au_assert("CBC decrypt trailing guard", guard(storage+len+1, sizeof(storage)-len-1));
      au_eq("CBC decrypt preserves IV", memcmp(iv, saved_iv, sizeof(iv)), 0);
      au_eq("CBC decrypt preserves separate input", memcmp(cipher, saved_cipher, sizeof(cipher)), 0);
    }
  }
  memset(storage, 0xa5, sizeof(storage));
  memcpy(snapshot, storage, sizeof(storage));
  const size_t invalid[] = {1, 7, 15, 17, 31, 33, 63, SIZE_MAX};
  for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i) {
    int result = aes_whitebox_decrypt_cbc(iv, cipher, invalid[i], storage+1);
    au_eq("CBC decrypt rejects partial block", result, AES_WHITEBOX_INVALID_LENGTH);
    au_eq("CBC decrypt failure preserves output", memcmp(storage, snapshot, sizeof(storage)), 0);
  }
  au_eq("CBC decrypt null IV", aes_whitebox_decrypt_cbc(NULL, cipher, 16, storage+1), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC decrypt null input", aes_whitebox_decrypt_cbc(iv, NULL, 16, storage+1), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC decrypt null output", aes_whitebox_decrypt_cbc(iv, cipher, 16, NULL), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC decrypt argument failures preserve output", memcmp(storage, snapshot, sizeof(storage)), 0);
  au_eq("CBC decrypt empty allows null", aes_whitebox_decrypt_cbc(NULL, NULL, 0, NULL), AES_WHITEBOX_OK);
  au_eq("CBC decrypt rejects length before pointer access", aes_whitebox_decrypt_cbc(NULL, NULL, SIZE_MAX, NULL), AES_WHITEBOX_INVALID_LENGTH);
  memcpy(storage+1, cipher, sizeof(cipher));
  memcpy(snapshot, storage, sizeof(storage));
  au_eq("CBC decrypt invalid in-place length", aes_whitebox_decrypt_cbc(iv, storage+1, 17, storage+1), AES_WHITEBOX_INVALID_LENGTH);
  au_eq("CBC decrypt failure preserves in-place input", memcmp(storage, snapshot, sizeof(storage)), 0);
  au_eq("CBC decrypt failures preserve IV", memcmp(iv, saved_iv, sizeof(iv)), 0);
  // CBC's IV XOR lets this independent NIST ciphertext produce any chosen
  // final plaintext block, without relying on our encryption implementation.
  uint8_t padded_iv[16], bad_iv[16], desired[16];
  for (unsigned padding = 1; padding <= 16; ++padding) {
    size_t required = 16-padding;
    memcpy(desired, plain, required);
    memset(desired+required, (int)padding, padding);
    for (int j = 0; j < 16; ++j) padded_iv[j] = iv[j] ^ plain[j] ^ desired[j];
    for (int in_place = 0; in_place < 2; ++in_place) {
      memset(storage, 0xa5, sizeof(storage));
      if (in_place) memcpy(storage+1, cipher, 16);
      memcpy(snapshot, storage, sizeof(storage));
      size_t written = 123;
      int result = aes_whitebox_decrypt_cbc_pkcs7(padded_iv, in_place ? storage+1 : cipher,
                                                16, storage+1, required, &written);
      au_eq("PKCS7 decrypt all pad lengths", result, AES_WHITEBOX_OK);
      au_assert("PKCS7 decrypt written", written == required);
      au_eq("PKCS7 decrypt chosen plaintext", memcmp(storage+1, plain, required), 0);
      au_eq("PKCS7 decrypt leading guard", storage[0], 0xa5);
      au_eq("PKCS7 decrypt only writes unpadded bytes", memcmp(storage+required+1, snapshot+required+1, sizeof(storage)-required-1), 0);
      if (required) {
        memset(storage, 0xa5, sizeof(storage));
        if (in_place) memcpy(storage+1, cipher, 16);
        memcpy(snapshot, storage, sizeof(storage));
        written = 123;
        result = aes_whitebox_decrypt_cbc_pkcs7(padded_iv, in_place ? storage+1 : cipher,
                                               16, storage+1, required-1, &written);
        au_eq("PKCS7 decrypt capacity", result, AES_WHITEBOX_INSUFFICIENT_CAPACITY);
        au_eq("PKCS7 capacity preserves output", memcmp(storage, snapshot, sizeof(storage)), 0);
        au_assert("PKCS7 capacity preserves written", written == 123);
      }
    }
    // Corrupt each claimed padding byte, including the last byte.
    for (size_t j = required; j < 16; ++j) {
      memcpy(bad_iv, padded_iv, sizeof(bad_iv));
      bad_iv[j] ^= j == 15 ? padding : 1;
      for (int in_place = 0; in_place < 2; ++in_place) {
        memset(storage, 0xa5, sizeof(storage));
        if (in_place) memcpy(storage+1, cipher, 16);
        memcpy(snapshot, storage, sizeof(storage));
        size_t written = 123;
        int result = aes_whitebox_decrypt_cbc_pkcs7(bad_iv, in_place ? storage+1 : cipher,
                                                  16, storage+1, 64, &written);
        au_eq("PKCS7 rejects corrupt padding byte", result, AES_WHITEBOX_INVALID_PADDING);
        au_eq("PKCS7 invalid padding preserves output", memcmp(storage, snapshot, sizeof(storage)), 0);
        au_assert("PKCS7 invalid padding preserves written", written == 123);
      }
    }
  }
  const unsigned bad_pads[] = {0, 17, 255};
  memset(storage, 0xa5, sizeof(storage));
  memcpy(snapshot, storage, sizeof(storage));
  size_t written = 123;
  for (size_t i = 0; i < sizeof(bad_pads)/sizeof(bad_pads[0]); ++i) {
    memcpy(bad_iv, iv, sizeof(iv));
    bad_iv[15] ^= plain[15] ^ bad_pads[i];
    int result = aes_whitebox_decrypt_cbc_pkcs7(bad_iv, cipher, 16, storage+1, 64, &written);
    au_eq("PKCS7 rejects pad length outside 1..16", result, AES_WHITEBOX_INVALID_PADDING);
  }
  const size_t bad_lengths[] = {0, 1, 15, 17, 31, SIZE_MAX};
  for (size_t i = 0; i < sizeof(bad_lengths)/sizeof(bad_lengths[0]); ++i) {
    int result = aes_whitebox_decrypt_cbc_pkcs7(iv, cipher, bad_lengths[i], storage+1, 64, &written);
    au_eq("PKCS7 rejects ciphertext length", result, AES_WHITEBOX_INVALID_LENGTH);
  }
  au_eq("PKCS7 null IV", aes_whitebox_decrypt_cbc_pkcs7(NULL, cipher, 16, storage+1, 64, &written), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("PKCS7 null ciphertext", aes_whitebox_decrypt_cbc_pkcs7(iv, NULL, 16, storage+1, 64, &written), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("PKCS7 null output", aes_whitebox_decrypt_cbc_pkcs7(iv, cipher, 16, NULL, 64, &written), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("PKCS7 null written", aes_whitebox_decrypt_cbc_pkcs7(iv, cipher, 16, storage+1, 64, NULL), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("PKCS7 failures preserve output", memcmp(storage, snapshot, sizeof(storage)), 0);
  au_assert("PKCS7 failures preserve written", written == 123);
  au_eq("PKCS7 preserves IV", memcmp(iv, saved_iv, sizeof(iv)), 0);
  au_eq("PKCS7 preserves ciphertext", memcmp(cipher, saved_cipher, sizeof(cipher)), 0);

}
au_endmain
