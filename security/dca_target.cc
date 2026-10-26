// One-block raw AES oracle, identical CLI before and after the changes.
#include <stdio.h>
#include "hex.h"
#ifdef AES_DCA_LEGACY
#include "aes_whitebox.cc"
#else
#include "aes_whitebox.h"
#endif

int main(int argc, char** argv) {
  uint8_t block[16];
  if (argc != 2 || !parse_hex(argv[1], block, sizeof(block))) {
    fputs("expected one 32-digit hexadecimal plaintext block\n", stderr);
    return 1;
  }
#ifdef AES_DCA_LEGACY
  Cipher(block);
#else
  aes_whitebox_encode_input_block(block, block);
  aes_whitebox_encrypt_encoded_block(block, block);
  aes_whitebox_decode_output_block(block, block);
#endif
  for (uint8_t byte : block) printf("%02x", byte);
  putchar('\n');
  return 0;
}
