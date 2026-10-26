// NIST SP 800-38A F.2.1/F.2.3/F.2.5 and CBC API boundary checks.
#include <stdio.h>
#include <string.h>

#include "aes_whitebox.h"
#include "aunit.h"
#include "hex.h"

static int is_guard(const uint8_t* bytes, size_t len) {
  for (size_t i = 0; i < len; ++i)
    if (bytes[i] != 0xa5) return 0;
  return 1;
}

au_main
{
  uint8_t plain[64], iv[16], expected[64];
  if (argc != 4 || !parse_hex(argv[1], plain, sizeof(plain)) ||
      !parse_hex(argv[2], iv, sizeof(iv)) ||
      !parse_hex(argv[3], expected, sizeof(expected))) {
    fputs("expected 64-byte plaintext, 16-byte IV and 64-byte ciphertext in hex\n", stderr);
    return 1;
  }
  uint8_t saved_plain[64], saved_iv[16], storage[66], snapshot[66];
  memcpy(saved_plain, plain, sizeof(plain));
  memcpy(saved_iv, iv, sizeof(iv));
  const size_t lengths[] = {0, 16, 32, 48, 64};
  for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); ++i) {
    size_t len = lengths[i];
    memset(storage, 0xa5, sizeof(storage));
    au_eq("CBC success", aes_whitebox_encrypt_cbc(iv, plain, len, storage+1), AES_WHITEBOX_OK);
    au_eq("CBC NIST vector prefix", memcmp(storage+1, expected, len), 0);
    au_eq("CBC preserves input", memcmp(plain, saved_plain, sizeof(plain)), 0);
    au_eq("CBC preserves IV", memcmp(iv, saved_iv, sizeof(iv)), 0);
    au_eq("CBC leading guard", storage[0], 0xa5);
    au_assert("CBC trailing guard", is_guard(storage+len+1, sizeof(storage)-len-1));

    memset(storage, 0xa5, sizeof(storage));
    memcpy(storage+1, plain, len);
    au_eq("CBC in-place success", aes_whitebox_encrypt_cbc(iv, storage+1, len, storage+1), AES_WHITEBOX_OK);
    au_eq("CBC in-place vector", memcmp(storage+1, expected, len), 0);
    au_eq("CBC in-place leading guard", storage[0], 0xa5);
    au_assert("CBC in-place trailing guard", is_guard(storage+len+1, sizeof(storage)-len-1));
  }

  const size_t invalid_lengths[] = {1, 7, 15, 17, 31, 33, 63, SIZE_MAX};
  memset(storage, 0xa5, sizeof(storage));
  memcpy(snapshot, storage, sizeof(storage));
  for (size_t i = 0; i < sizeof(invalid_lengths)/sizeof(invalid_lengths[0]); ++i) {
    au_eq("CBC rejects partial blocks", aes_whitebox_encrypt_cbc(iv, plain, invalid_lengths[i], storage+1), AES_WHITEBOX_INVALID_LENGTH);
    au_eq("CBC failure preserves output", memcmp(storage, snapshot, sizeof(storage)), 0);
  }
  au_eq("CBC rejects null IV", aes_whitebox_encrypt_cbc(NULL, plain, 16, storage+1), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC rejects null input", aes_whitebox_encrypt_cbc(iv, NULL, 16, storage+1), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC rejects null output", aes_whitebox_encrypt_cbc(iv, plain, 16, NULL), AES_WHITEBOX_INVALID_ARGUMENT);
  au_eq("CBC null argument failure preserves output", memcmp(storage, snapshot, sizeof(storage)), 0);
  au_eq("CBC rejects length before accessing pointers", aes_whitebox_encrypt_cbc(NULL, NULL, SIZE_MAX, NULL), AES_WHITEBOX_INVALID_LENGTH);
  au_eq("CBC empty input allows null pointers", aes_whitebox_encrypt_cbc(NULL, NULL, 0, NULL), AES_WHITEBOX_OK);

  memcpy(storage+1, plain, sizeof(plain));
  memcpy(snapshot, storage, sizeof(storage));
  au_eq("CBC rejects invalid in-place length", aes_whitebox_encrypt_cbc(iv, storage+1, 17, storage+1), AES_WHITEBOX_INVALID_LENGTH);
  au_eq("CBC failure preserves in-place data", memcmp(storage, snapshot, sizeof(storage)), 0);
  au_eq("CBC failures preserve IV", memcmp(iv, saved_iv, sizeof(iv)), 0);
}
au_endmain
