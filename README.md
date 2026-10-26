# AES Whitebox

A research implementation of table-based white-box AES, based on
[Chow et al.](https://www.cs.colorado.edu/~jrblack/class/csci7000/s03/project/oorschot-whitebox.pdf)
and [Muir's tutorial](https://eprint.iacr.org/2013/104.pdf).
Encryption and optional decryption for AES-128/192/256 are checked against
NIST SP 800-38A vectors and an independent
OpenSSL oracle. Experimental 512/1024/2048/4096-bit key variants remain available
in the encryption generator; they are not standard AES and are not covered by
those tests. Decryption rejects these experimental key lengths.

The generator combines keyed T-boxes with random invertible L and MB matrices.
Both Ty and MBL stages have separate XOR networks. Every internal nibble edge
has an independently sampled 4-bit permutation; its inverse is folded into the
consuming table. No internal inverse-permutation arrays are emitted. The first
and last boundaries also use independent nibble permutations as external
encodings. These changes preserve AES semantics; they do not establish resistance
to key extraction or DCA. See [the security evaluation](security/README.md).

## Build and test

Dependencies: a C++11 compiler, Make, NTL, and GMP. Python 3 is used for robustness
and equivalence tests; the latter also requires the `openssl` command.

macOS with Homebrew:

```sh
brew install ntl
make -j3
make equivalence
# Optional inverse core and CBC decryption:
make -j3 test-decrypt
make equivalence-decrypt
```

Ubuntu/Debian:

```sh
sudo apt-get update
sudo apt-get install build-essential libntl-dev libgmp-dev python3 openssl
make -j3
make equivalence
# Optional inverse core and CBC decryption:
make -j3 test-decrypt
make equivalence-decrypt
```

The Makefile discovers Homebrew prefixes. Override `NTL_PREFIX`, `GMP_PREFIX`,
`CPPFLAGS`, or `LDFLAGS` for other installations. Each key size has independent
outputs in `build/aes128/`, `build/aes192/`, or `build/aes256/`; parallel builds
are supported. Optional inverse outputs live in each key directory's `decrypt/`
subdirectory. Default `make` builds/tests only encryption. `make test-decrypt`
builds/tests decryption independently. Test targets run on every invocation. Generated dependency
files track included headers and tables.

`make test` runs NIST vectors, boundary lengths (including 0/15/16/17/33 bytes),
exact in-place encryption/decryption, output bounds, invalid CLI/hex input, and
output-file error handling. CBC encryption also has AES-128/192/256 NIST vectors,
full-block prefixes, invalid lengths/null arguments, and in-place/bounds tests.
PKCS#7 tests cover every length from 0 through 64, padded output capacity,
size overflow, and failure preservation.
`make equivalence` checks three seeds for each
standard key size against OpenSSL, including encoded-core integration,
CFB/OFB/CTR, raw and PKCS#7 CBC encryption, counter carry, deterministic replay, and a core-only build.
To increase the number of generated implementations:

```sh
python3 tests/equivalence.py --seeds 1,2,3,4,5 --blocks 1024
```

## Generate an implementation

```sh
mkdir -p build/custom
./build/aes_whitebox_compiler aes128 2b7e151628aed2a6abf7158809cf4f3c \
  --seed 42 \
  --output build/custom/aes_whitebox_tables.cc \
  --helpers build/custom/external_encodings.cc
```

`--seed` is an optional nonnegative decimal integer. Omitting it uses NTL's
default random initialization. A seed reproduces both files for the same key,
generator, and NTL implementation; reproducibility across NTL versions is not
promised. Fixed/public seeds are for reproducibility and testing, not added
protection. Record the generator/toolchain versions and artifact hashes for audits.

Without path options the outputs are `aes_whitebox_tables.cc` and
`aes_whitebox_tables.cc.helpers.cc`. Each file is written to a unique temporary
file beside its destination; writes and close are checked before atomic rename.
The two renames are **not a two-file transaction**: distribute and replace the
pair together, and do not compile while a separate process replaces them.
The Makefile serializes generation and compilation for each pair.

### Ordinary-byte mode API

Compile `aes_whitebox.cc` with the generated directory on the include path,
and link the matching `external_encodings.cc`. The private shared header
`aes_whitebox_internal.h` must accompany both runtime source files:

```sh
c++ -std=c++11 -Ibuild/custom -c aes_whitebox.cc -o build/custom/aes_whitebox.o
c++ -std=c++11 -c build/custom/external_encodings.cc -o build/custom/external_encodings.o
```

The C-compatible API in `aes_whitebox.h` is:

```c
void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m, size_t len, uint8_t* c);
void aes_whitebox_decrypt_cfb(const uint8_t iv[16], const uint8_t* c, size_t len, uint8_t* m);
void aes_whitebox_encrypt_ofb(const uint8_t iv[16], const uint8_t* m, size_t len, uint8_t* c);
void aes_whitebox_decrypt_ofb(const uint8_t iv[16], const uint8_t* c, size_t len, uint8_t* m);
void aes_whitebox_encrypt_ctr(const uint8_t nonce[16], const uint8_t* m, size_t len, uint8_t* c);
void aes_whitebox_decrypt_ctr(const uint8_t nonce[16], const uint8_t* c, size_t len, uint8_t* m);
```

These functions accept ordinary plaintext/ciphertext bytes, including partial
blocks. CFB uses 128-bit feedback. Exact in-place operation is supported; other
input/output overlap is unsupported. Every call restarts from its IV/counter;
separate calls are not a streaming interface. CTR increments the entire 128-bit
initial counter in big-endian order. The caller must ensure that counter blocks
are never reused under the same key and that the counter does not wrap. CFB IVs
must be unpredictable, and OFB IVs must be unique for a key. These modes do not
provide authentication or tamper detection.

### CBC encryption without padding

```c
int aes_whitebox_encrypt_cbc(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c);
```

This API uses the same generated encryption tables and adapters. It accepts
ordinary bytes and requires `len` to be a multiple of 16. No padding is added;
the output is exactly `len` bytes, and the caller must supply that capacity.
It supports exact in-place encryption; other partial overlap is unsupported.
The IV must not overlap the output buffer, is preserved, and must be
unpredictable for each message. Each call starts a new chain from the given IV.
CBC provides no authentication or tamper detection.

The return values are `AES_WHITEBOX_OK` (0), `AES_WHITEBOX_INVALID_LENGTH` (-1),
and `AES_WHITEBOX_INVALID_ARGUMENT` (-2). Length is validated first. For a
nonempty message, IV, input, and output must all be non-null. Errors are returned
before any output is written. Zero length returns success without accessing any
pointer, so `aes_whitebox_encrypt_cbc(NULL, NULL, 0, NULL)` is valid.

CBC encryption functions are omitted from
`AES_WHITEBOX_CORE_ONLY` builds, as are the other ordinary-byte mode wrappers.

### CBC encryption with PKCS#7 padding

```c
int aes_whitebox_encrypt_cbc_pkcs7(const uint8_t iv[16], const uint8_t* m,
    size_t len, uint8_t* c, size_t capacity, size_t* written);
```

This function accepts arbitrary byte lengths. Padding consists of 1..16 copies
of the padding length. An empty message becomes one encrypted padding block;
block-aligned input always gets an extra block. The output size is
`len + (16 - len % 16)`. The implementation checks this addition for overflow
before reading input or writing output, returning `AES_WHITEBOX_INVALID_LENGTH`
if it cannot be represented by `size_t`.

Supply an output buffer with at least that capacity and a non-null `written`
pointer. On success, `*written` receives the ciphertext length. Insufficient
capacity returns `AES_WHITEBOX_INSUFFICIENT_CAPACITY` (-3). Other null arguments
return `AES_WHITEBOX_INVALID_ARGUMENT`; only the plaintext may be null when
`len == 0`. Empty input still requires a valid IV and a 16-byte output buffer.
There is no null-output size-query mode. On every error, both the output buffer
and `*written` are unchanged.

Exact in-place operation is supported when the allocation has room for the
padded result. Other buffer overlap is unsupported, the IV must not overlap
output, and `written` must not overlap any input/output/IV buffer. The same IV,
per-call chaining, and authentication limitations as raw CBC apply. The function
uses the existing encryption tables and does not allocate memory dynamically.

### Optional inverse white-box core and CBC decryption

Generate only decryption tables (standard AES-128/192/256):

```sh
mkdir -p build/custom-decrypt
./build/aes_whitebox_compiler aes128 2b7e151628aed2a6abf7158809cf4f3c \
  --seed 42 --direction decrypt \
  --output build/custom-decrypt/aes_whitebox_decrypt_tables.cc \
  --helpers build/custom-decrypt/external_encodings.cc
c++ -std=c++11 -Ibuild/custom-decrypt -c aes_whitebox_decrypt.cc -o build/custom-decrypt/core.o
c++ -std=c++11 -c build/custom-decrypt/external_encodings.cc -o build/custom-decrypt/helpers.o
```

Link these two objects for a standalone inverse runtime; `aes_whitebox.cc` and
its encryption tables are not needed. The public ordinary-byte API is:

```c
int aes_whitebox_decrypt_cbc(const uint8_t iv[16], const uint8_t* c,
    size_t len, uint8_t* m);
```

It decrypts full blocks without removing padding. Output capacity must be at
least `len`. The zero-length, status, IV preservation, invalid-argument and
in-place contracts match unpadded CBC encryption. It saves each ciphertext block
before writing plaintext, so exact in-place decryption preserves the feedback
chain. PKCS#7 decryption/unpadding is not implemented.

For externally encoded integration, the matching helpers and inverse core are:

```c
void aes_whitebox_decrypt_encode_input_block(const uint8_t in[16], uint8_t out[16]);
void aes_whitebox_decrypt_encoded_block(const uint8_t in[16], uint8_t out[16]);
void aes_whitebox_decrypt_decode_output_block(const uint8_t in[16], uint8_t out[16]);
```

Their composition equals standard AES decryption. Compile the inverse runtime
with `-DAES_WHITEBOX_CORE_ONLY` to exclude the ordinary-byte CBC wrapper and link
without the inverse helper object. Each direction has its own external mappings;
encryption helpers cannot be used for decryption.

`--direction encrypt` is the default and retains the existing output format and
seeded encryption artifacts. `--direction both` writes the ordinary encryption
pair plus `aes_whitebox_decrypt_tables.cc` beside the encryption table file and
its `.helpers.cc` companion. With `both`, override the additional pair using
`--decrypt-output` and `--decrypt-helpers`; `--output` and `--helpers` still refer
to encryption. In `decrypt` mode they refer to decryption. With no path options,
`decrypt` uses `aes_whitebox_decrypt_tables.cc` and its `.helpers.cc` companion.
All destinations must be distinct. Each file is replaced atomically, but multiple
pairs are not published as a transaction; distribute matching artifacts together.

Explicit seeds use a separate decryption seed domain, so a given numeric seed
produces identical inverse artifacts in `decrypt` and `both` modes. The
previous encryption random stream is preserved. The same toolchain/NTL-version
reproducibility limits apply as for encryption.

The inverse generator folds the last round key into the first inverse S-box
lookup, then combines inverse substitution and round-key addition before inverse
column mixing. It uses the same L/MB protections and independently encoded XOR
networks, with inverse row permutations applied at all table boundaries. Keys
and inverse S-box construction stay in the generator; the deployed runtime
contains generated tables and no ordinary key schedule.

`make equivalence-decrypt` compares arbitrary ciphertexts directly against
OpenSSL decryption for three seeds and all standard key sizes. It checks
isolated inverse, combined, and core-only builds, raw CBC, exact in-place
operation, output bounds, seed replay and encryption artifact compatibility.
`make test-decrypt` adds the NIST CBC vectors and invalid-input checks.

### Externally encoded core

The separately generated helper file exports:

```c
void aes_whitebox_encode_input_block(const uint8_t in[16], uint8_t out[16]);
void aes_whitebox_decode_output_block(const uint8_t in[16], uint8_t out[16]);
```

The core exports:

```c
void aes_whitebox_encrypt_encoded_block(const uint8_t in[16], uint8_t out[16]);
```

Its contract is `decode_output(core(encode_input(plain))) == AES_key(plain)`.
All three support exact in-place use. These are position-dependent pairs of
4-bit permutations, not arbitrary 128-bit external bijections. There is no raw
AES input/output boundary inside the encoded core.

To deploy only the encoded core, compile `aes_whitebox.cc` with
`-DAES_WHITEBOX_CORE_ONLY` and omit the helper object. The CFB/OFB/CTR wrappers
are excluded from that build. Keep the helper mappings in the appropriate host
component if the integration requires separate encodings. Linking the helpers
into an attacker-visible binary makes those external mappings available to that
attacker; external encoding alone is not evidence of protection.

## Table storage

Values below are data bytes, excluding source formatting and executable overhead.
Separate Ty and MBL XOR networks increase storage compared to the original code.

| Table | AES-128 | AES-192 | AES-256 |
|---|---:|---:|---:|
| Both XOR networks | 442,368 | 540,672 | 638,976 |
| Tyboxes | 147,456 | 180,224 | 212,992 |
| MBL | 147,456 | 180,224 | 212,992 |
| Last round | 4,096 | 4,096 | 4,096 |
| Core total | 741,376 | 905,216 | 1,069,056 |
| External helper mappings | 8,192 | 8,192 | 8,192 |

The optional inverse direction has the same table shapes and raw storage sizes.
Linking both directions doubles these table totals; encryption-only builds carry
no inverse tables. This storage statement excludes executable alignment and code.

`aes.cc`, `aes.h`, and `aes_private.h` also provide the original reference AES
implementation, which is not required by the generated runtime.

## Security evaluation

The original project already acknowledges key-extraction attacks on Chow-style
white-box AES. Longer experimental keys, more tables, and functional equivalence
do not prove stronger white-box security. The current implementation has no
completed before/after DCA measurement. See [security/README.md](security/README.md)
for prepared targets, the measured environment limitation, and the procedure for
recording actual recovery and trace counts.
