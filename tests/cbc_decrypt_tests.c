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
}
au_endmain
