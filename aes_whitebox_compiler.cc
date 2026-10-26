// Copyright 2019 AES WBC Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <array>
#include <vector>
#include <string>
#include <utility>
#include <stdexcept>
#include <sstream>
#include <NTL/ZZ.h>

#include "hex.h"

#include <NTL/mat_GF2.h>

#include "aes_private.h"

namespace {

using WordTables = std::array<std::array<uint32_t, 256>, 16>;
using LastTables = std::array<std::array<uint8_t, 256>, 16>;

void err_quit(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  fflush(stderr);
  va_end(ap);

  exit(1);
}

void read_key(const char *in, uint8_t* key, size_t size) {
  if (!parse_hex(in, key, size))
    err_quit("Invalid key (expected exactly %zu hexadecimal digits)", size * 2);
}

template<typename T>
inline NTL::vec_GF2 from_scalar(T in);

template<>
inline NTL::vec_GF2 from_scalar(uint8_t in) {
  NTL::vec_GF2 result;
  result.SetLength(8);
  for (int i = 0; i < 8; i++) {
    result[7 - i] = ((in >> i) & 1);
  }
  return result;
}

template<>
inline NTL::vec_GF2 from_scalar(uint32_t in) {
  NTL::vec_GF2 result;
  result.SetLength(32);
  for (int i = 0; i < 32; i++) {
    result[31 - i] = ((in >> i) & 1);
  }
  return result;
}

template<typename T>
inline T to_scalar(const NTL::vec_GF2& in);

template<>
inline uint8_t to_scalar(const NTL::vec_GF2& in) {
  uint8_t result = 0;
  for (int i = 0; i < 2; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
  }
  return result;
}

template<>
inline uint32_t to_scalar(const NTL::vec_GF2& in) {
  uint32_t result = 0;
  for (int i = 0; i < 8; i++) {
    long i0 = NTL::rep(in[i*4+0]), i1 = NTL::rep(in[i*4+1]),
         i2 = NTL::rep(in[i*4+2]), i3 = NTL::rep(in[i*4+3]);
    result = (result << 4) | (i0 << 3) | (i1 << 2) | (i2 << 1) | (i3 << 0);
  }
  return result;
}

template<typename T>
inline T mul(const NTL::mat_GF2& mat, T x) {
  return to_scalar<T>(mat * from_scalar<T>(x));
}

NTL::mat_GF2 GenerateGF2RandomMatrix(int dimension) {
  NTL::mat_GF2 mat(NTL::INIT_SIZE, dimension, dimension);
  for (int i = 0; i < dimension; i++) {
    for (int j = 0; j < dimension; j++) {
      mat[i][j] = NTL::random_GF2();
    }
  }
  return mat;
}

struct MatrixPair { NTL::mat_GF2 forward, inverse; };

MatrixPair GenerateRandomGF2InvertibleMatrix(int dimension) {
  for (;;) {
    NTL::mat_GF2 result = GenerateGF2RandomMatrix(dimension);
    NTL::GF2 determinant;
    NTL::mat_GF2 inverse;
    NTL::inv(determinant, inverse, result);
    if (determinant != 0)
      return {std::move(result), std::move(inverse)};
  }
}

// Calculate the T-boxes, which is a combination of the AddRoundKeyAfterShift
// and the SubBytes functions.
void CalculateTboxes(const uint32_t roundKey[],
    std::vector<LastTables>& Tboxes, int Nr) {
  for (int r = 0; r < Nr; r++) {
    for (int x = 0; x < 256; x++) {
      uint8_t state[16] = {
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x,
        (uint8_t)x, (uint8_t)x, (uint8_t)x, (uint8_t)x
      };
      AddRoundKeyAfterShift(state, &roundKey[r*4]);
      SubBytes(state);
      if (r == Nr-1) {
        AddRoundKey(state, &roundKey[4*Nr]);
      }
      for (int i = 0; i < 16; i++) {
        Tboxes[r][i][x] = state[i];
      }
    }
  }
}

void CalculateTy(uint8_t Ty[4][256][4]) {
  for (int x = 0; x < 256; x++) {
    Ty[0][x][0] = gf_mul[x][0];
    Ty[0][x][1] = gf_mul[x][1];
    Ty[0][x][2] = x;
    Ty[0][x][3] = x;

    Ty[1][x][0] = x;
    Ty[1][x][1] = gf_mul[x][0];
    Ty[1][x][2] = gf_mul[x][1];
    Ty[1][x][3] = x;

    Ty[2][x][0] = x;
    Ty[2][x][1] = x;
    Ty[2][x][2] = gf_mul[x][0];
    Ty[2][x][3] = gf_mul[x][1];

    Ty[3][x][0] = gf_mul[x][1];
    Ty[3][x][1] = x;
    Ty[3][x][2] = x;
    Ty[3][x][3] = gf_mul[x][0];
  }
}

// Fold the initial last-round key into the first inverse S-box table.
// Every subsequent table combines InvSubBytes and its following AddRoundKey.
void CalculateInverseTboxes(const uint32_t roundKey[],
    std::vector<LastTables>& tables, int Nr) {
  uint8_t inverse_sbox[256];
  for (int x = 0; x < 256; ++x)
    inverse_sbox[Sbox[x >> 4][x & 15]] = x;
  for (int r = 0; r < Nr; ++r) {
    for (int i = 0; i < 16; ++i) {
      int source = InvShiftRowsTab[i];
      uint8_t initial_key = roundKey[Nr*4 + source/4] >> (24-8*(source%4));
      uint8_t key = roundKey[(Nr-1-r)*4 + i/4] >> (24-8*(i%4));
      for (int x = 0; x < 256; ++x)
        tables[r][i][x] = inverse_sbox[x ^ (r == 0 ? initial_key : 0)] ^ key;
    }
  }
}

void CalculateInverseTy(uint8_t ty[4][256][4]) {
  // Indices into gf_mul: 9, 11, 13, 14 are columns 2, 3, 4, 5.
  constexpr int coefficients[4][4] = {
    {5, 3, 4, 2}, {2, 5, 3, 4}, {4, 2, 5, 3}, {3, 4, 2, 5}
  };
  for (int byte = 0; byte < 4; ++byte)
    for (int x = 0; x < 256; ++x)
      for (int lane = 0; lane < 4; ++lane)
        ty[byte][x][lane] = gf_mul[x][coefficients[byte][lane]];
}

void CalculateTyBoxes(uint32_t roundKey[],
    std::vector<WordTables>& Tyboxes, LastTables& TboxesLast,
    std::vector<WordTables>& MBL, bool enableL, bool enableMB, int Nr, bool decrypt = false) {
  std::vector<LastTables> Tboxes(Nr);
  uint8_t Ty[4][256][4];

  if (decrypt) {
    CalculateInverseTboxes(roundKey, Tboxes, Nr);
    CalculateInverseTy(Ty);
  } else {
    CalculateTboxes(roundKey, Tboxes, Nr);
    CalculateTy(Ty);
  }
  const int* inverse_shift = decrypt ? ShiftRowsTab : InvShiftRowsTab;

  for (int r = 0; r < Nr-1; r++) {
    for (int x = 0; x < 256; x++) {
      for (int j = 0; j < 4; j++) {
        for (int i = 0; i < 4; i++) {
          uint32_t v0 = Ty[0][Tboxes[r][j*4 + i][x]][i],
                   v1 = Ty[1][Tboxes[r][j*4 + i][x]][i],
                   v2 = Ty[2][Tboxes[r][j*4 + i][x]][i],
                   v3 = Ty[3][Tboxes[r][j*4 + i][x]][i];
          Tyboxes[r][j*4 + i][x] = (v0 << 24) | (v1 << 16) | (v2 << 8) | v3;
          MBL[r][j*4 + i][x] = x << ((3 - i) << 3);
        }
      }
    }
  }

  for (int x = 0; x < 256; x++) {
    for (int i = 0; i < 16; i++) {
      TboxesLast[i][x] = Tboxes[Nr-1][i][x];
    }
  }

  if (enableMB) {
    std::vector<std::array<MatrixPair, 4>> MB(Nr-1);
    for (int r = 0; r < Nr-1; r++) {
      for (int i = 0; i < 4; i++) {
        MB[r][i] = GenerateRandomGF2InvertibleMatrix(32);
      }
    }

    // When applying MB and inv(MB), the operation is quite easy; there is no
    // need to safeguard the existing table, as it is a simple substitution. 
    for (int r = 0; r < Nr-1; r++) {
      for (int x = 0; x < 256; x++) {
        for (int i = 0; i < 16; i++) {
          Tyboxes[r][i][x] = mul<uint32_t>(MB[r][i >> 2].forward, Tyboxes[r][i][x]);
          MBL[r][i][x] = mul<uint32_t>(MB[r][i >> 2].inverse, MBL[r][i][x]);
        }
      }
    }
  }

  if (enableL) {
    std::vector<std::array<MatrixPair, 16>> L(Nr-1);
    for (int r = 0; r < Nr-1; r++) {
      for (int i = 0; i < 16; i++) {
        L[r][i] = GenerateRandomGF2InvertibleMatrix(8);
      }
    }

    // When applying L and inv(L), things get a little tricky. As it involves
    // non-linear substitutions, the original table has to be copied before
    // being updated.
    for (int r = 0; r < Nr-1; r++) {
      
      if (r > 0) {
        // Rounds 1 to Nr-1 are reversed here.
        for (int i = 0; i < 16; i++) {
          uint32_t oldTyboxes[256];
          for (int x = 0; x < 256; x++)
            oldTyboxes[x] = Tyboxes[r][i][x];
          for (int x = 0; x < 256; x++)
            Tyboxes[r][i][x] = oldTyboxes[mul<uint8_t>(L[r-1][i].inverse, x)];
        }
      }
  
      // Apply the L transformation at each round.
      for (int j = 0; j < 4; ++j) {
        for (int x = 0; x < 256; x++) {
          uint32_t out0 = MBL[r][j*4 + 0][x];
          uint32_t out1 = MBL[r][j*4 + 1][x];
          uint32_t out2 = MBL[r][j*4 + 2][x];
          uint32_t out3 = MBL[r][j*4 + 3][x];
  
          MBL[r][j*4 + 0][x] = (mul<uint8_t>(L[r][inverse_shift[j*4 + 0]].forward, out0 >> 24) << 24)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 1]].forward, out0 >> 16) << 16)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 2]].forward, out0 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 3]].forward, out0 >>  0) <<  0);
  
          MBL[r][j*4 + 1][x] = (mul<uint8_t>(L[r][inverse_shift[j*4 + 0]].forward, out1 >> 24) << 24)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 1]].forward, out1 >> 16) << 16)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 2]].forward, out1 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 3]].forward, out1 >>  0) <<  0);
  
          MBL[r][j*4 + 2][x] = (mul<uint8_t>(L[r][inverse_shift[j*4 + 0]].forward, out2 >> 24) << 24)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 1]].forward, out2 >> 16) << 16)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 2]].forward, out2 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 3]].forward, out2 >>  0) <<  0);
  
          MBL[r][j*4 + 3][x] = (mul<uint8_t>(L[r][inverse_shift[j*4 + 0]].forward, out3 >> 24) << 24)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 1]].forward, out3 >> 16) << 16)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 2]].forward, out3 >>  8) <<  8)
                             | (mul<uint8_t>(L[r][inverse_shift[j*4 + 3]].forward, out3 >>  0) <<  0);
        }
      }
    }
  
    // The last and final round 9 is reversed here.
    for (int i = 0; i < 16; i++) {
      uint8_t oldTboxesLast[256];
      for (int x = 0; x < 256; x++)
        oldTboxesLast[x] = TboxesLast[i][x];
      for (int x = 0; x < 256; x++)
        TboxesLast[i][x] = oldTboxesLast[mul<uint8_t>(L[Nr-2][i].inverse, x)];
    }
  }
}

// Every edge carries its own random nibble permutation. Decoding is folded
// into the consuming table; no internal inverse tables are emitted.
struct Encoding {
  uint8_t forward[16], inverse[16];
  Encoding() {
    for (int i = 0; i < 16; ++i) forward[i] = i;
    for (int i = 15; i > 0; --i)
      std::swap(forward[i], forward[NTL::RandomBnd(i + 1)]);
    for (int i = 0; i < 16; ++i) inverse[forward[i]] = i;
  }
};
using ByteEncoding = std::array<Encoding, 2>; // high nibble, low nibble
using Boundary = std::array<ByteEncoding, 16>;
using XorRound = std::array<std::array<std::array<uint8_t, 16>, 16>, 96>;

uint8_t encode_byte(const ByteEncoding& e, uint8_t x) {
  return (e[0].forward[x >> 4] << 4) | e[1].forward[x & 15];
}
uint8_t decode_byte(const ByteEncoding& e, uint8_t x) {
  return (e[0].inverse[x >> 4] << 4) | e[1].inverse[x & 15];
}

// One stage consists of four 8->32 tables per column and eight XOR trees.
void EncodeStage(WordTables& tables, XorRound& xors,
                 const Boundary& input, const Boundary& output, bool shift, bool decrypt = false) {
  const int* rows = decrypt ? InvShiftRowsTab : ShiftRowsTab;
  for (int col = 0; col < 4; ++col) {
    std::array<std::array<Encoding, 8>, 4> leaves;
    for (int lane = 0; lane < 4; ++lane) {
      const int pos = col * 4 + lane;
      auto old = tables[pos];
      for (int x = 0; x < 256; ++x) {
        uint32_t word = old[decode_byte(input[shift ? rows[pos] : pos], x)];
        uint32_t encoded = 0;
        for (int n = 0; n < 8; ++n)
          encoded |= uint32_t(leaves[lane][n].forward[(word >> (28-4*n)) & 15]) << (28-4*n);
        tables[pos][x] = encoded;
      }
    }
    for (int byte = 0; byte < 4; ++byte) {
      for (int half = 0; half < 2; ++half) {
        const int n = byte * 2 + half;
        Encoding left, right;
        const int base = col*24 + byte*6;
        for (int a = 0; a < 16; ++a) {
          for (int b = 0; b < 16; ++b) {
            xors[base + half*2][a][b] = left.forward[
                leaves[0][n].inverse[a] ^ leaves[1][n].inverse[b]];
            xors[base + half*2 + 1][a][b] = right.forward[
                leaves[2][n].inverse[a] ^ leaves[3][n].inverse[b]];
            xors[base + 4 + half][a][b] = output[col*4+byte][half].forward[
                left.inverse[a] ^ right.inverse[b]];
          }
        }
      }
    }
  }
}

// All formatted writes go through this checked function.
void checked_print(FILE* out, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int result = vfprintf(out, fmt, ap);
  va_end(ap);
  if (result < 0) throw std::runtime_error("writing generated source failed");
}

template<class T>
void Emit(FILE* out, const T& value) {
  checked_print(out, "%u,", unsigned(value));
}
template<class T, size_t N>
void Emit(FILE* out, const std::array<T, N>& values) {
  checked_print(out, "{\n");
  for (const auto& value : values) Emit(out, value);
  checked_print(out, "},\n");
}
template<class T>
void Emit(FILE* out, const std::vector<T>& values) {
  checked_print(out, "{\n");
  for (const auto& value : values) Emit(out, value);
  checked_print(out, "};\n");
}

// Unique temporary files live beside the destination, so rename is atomic.
class AtomicOutput {
 public:
  explicit AtomicOutput(const std::string& path) : path_(path), file_(nullptr) {
    std::string pattern = path + ".tmp.XXXXXX";
    std::vector<char> name(pattern.begin(), pattern.end());
    name.push_back(0);
    int fd = mkstemp(name.data());
    if (fd < 0) throw std::runtime_error("cannot create temporary output: " + path);
    temporary_ = name.data();
    file_ = fdopen(fd, "w");
    if (!file_) {
      close(fd);
      unlink(temporary_.c_str());
      throw std::runtime_error("cannot open temporary output: " + path);
    }
  }
  ~AtomicOutput() {
    if (file_) fclose(file_);
    if (!temporary_.empty()) unlink(temporary_.c_str());
  }
  FILE* get() { return file_; }
  void finish() {
    FILE* file = file_;
    file_ = nullptr;
    if (fclose(file) != 0) throw std::runtime_error("closing output failed: " + path_);
  }
  void commit() {
    if (rename(temporary_.c_str(), path_.c_str()) != 0)
      throw std::runtime_error("renaming output failed: " + path_);
    temporary_.clear();
  }
 private:
  std::string path_, temporary_;
  FILE* file_;
};

void EmitHelpers(FILE* out, const Boundary& input, const Boundary& output, bool decrypt) {
  checked_print(out, "// Generated external encoding adapters; keep outside the core.\n"
                     "#include <stdint.h>\nextern \"C\" {\n");
  for (int kind = 0; kind < 2; ++kind) {
    checked_print(out, "void aes_whitebox_%s%s_block(const uint8_t in[16], uint8_t out[16]) {\n"
                       "static const uint8_t map[16][256] = ",
                       decrypt ? "decrypt_" : "", kind == 0 ? "encode_input" : "decode_output");
    std::array<std::array<uint8_t, 256>, 16> map;
    for (int i = 0; i < 16; ++i)
      for (int x = 0; x < 256; ++x)
        map[i][x] = kind == 0 ? encode_byte(input[i], x) : decode_byte(output[i], x);
    checked_print(out, "{\n");
    for (const auto& row : map) Emit(out, row);
    checked_print(out, "}");
    checked_print(out, ";\nfor (int i=0;i<16;++i) out[i]=map[i][in[i]];\n}\n");
  }
  checked_print(out, "}\n");
}

void GenerateTables(const char* hexKey, int Nk, int Nr,
                    const std::string& path, const std::string& helpers, bool decrypt = false) {
  std::vector<uint8_t> key(Nk*4);
  std::vector<uint32_t> roundKey((Nr+1)*4);
  read_key(hexKey, key.data(), key.size());
  ExpandKeys(key.data(), roundKey.data(), Nk, Nr);

  std::vector<WordTables> ty(Nr-1), mbl(Nr-1);
  LastTables last;
  CalculateTyBoxes(roundKey.data(), ty, last, mbl, true, true, Nr, decrypt);
  Boundary external_input, external_output;
  Boundary previous = external_input;
  std::vector<XorRound> xor_ty(Nr-1), xor_mbl(Nr-1);
  for (int r = 0; r < Nr-1; ++r) {
    Boundary middle, next;
    EncodeStage(ty[r], xor_ty[r], previous, middle, true, decrypt);
    EncodeStage(mbl[r], xor_mbl[r], middle, next, false, decrypt);
    previous = next;
  }
  const int* rows = decrypt ? InvShiftRowsTab : ShiftRowsTab;
  for (int i = 0; i < 16; ++i) {
    auto old = last[i];
    for (int x = 0; x < 256; ++x)
      last[i][x] = encode_byte(external_output[i],
          old[decode_byte(previous[rows[i]], x)]);
  }
  AtomicOutput tables_file(path), helpers_file(helpers);
  FILE* out = tables_file.get();
  checked_print(out, "// Generated; do not edit.\nnamespace {\nconstexpr int Nr = %d;\n", Nr);
  checked_print(out, "constexpr uint32_t Tyboxes[%d][16][256] = ", Nr-1);
  Emit(out, ty);
  checked_print(out, "constexpr uint32_t MBL[%d][16][256] = ", Nr-1);
  Emit(out, mbl);
  checked_print(out, "constexpr uint8_t TboxesLast[16][256] = ");
  checked_print(out, "{\n");
  for (const auto& row : last) Emit(out, row);
  checked_print(out, "}");
  checked_print(out, ";\nconstexpr uint8_t XorTy[%d][96][16][16] = ", Nr-1);
  Emit(out, xor_ty);
  checked_print(out, "constexpr uint8_t XorMBL[%d][96][16][16] = ", Nr-1);
  Emit(out, xor_mbl);
  checked_print(out, "}\n");
  EmitHelpers(helpers_file.get(), external_input, external_output, decrypt);
  tables_file.finish();
  helpers_file.finish();
  // Each file is atomically replaced; this is not a two-file transaction.
  helpers_file.commit();
  tables_file.commit();
}

std::string CanonicalOutput(const std::string& path) {
  size_t slash = path.find_last_of('/');
  std::string parent = slash == std::string::npos ? "." : path.substr(0, slash + 1);
  std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
  char* resolved = realpath(parent.c_str(), nullptr);
  if (!resolved) throw std::runtime_error("cannot resolve output directory: " + parent);
  std::string result = std::string(resolved) + "/" + name;
  free(resolved);
  return result;
}

void syntax() {
  err_quit("Syntax: aes_whitebox_compiler <aes128|aes192|aes256|aes512|aes1024|aes2048|aes4096> "
           "<hex-key> [--seed <decimal>] [--direction encrypt|decrypt|both] "
           "[--output <tables.cc>] [--helpers <adapters.cc>] "
           "[--decrypt-output <tables.cc>] [--decrypt-helpers <adapters.cc>]");
}

}  // namespace

int main(int argc, char* argv[]) {
  try {
    if (argc < 3) syntax();
    int Nk = 0;
    const int sizes[] = {128, 192, 256, 512, 1024, 2048, 4096};
    for (int bits : sizes)
      if (std::string(argv[1]) == "aes" + std::to_string(bits)) Nk = bits / 32;
    if (!Nk) syntax();
    std::string output, helpers, decrypt_output, decrypt_helpers;
    std::string direction = "encrypt";
    bool seeded = false;
    NTL::ZZ seed;
    for (int i = 3; i < argc; i += 2) {
      if (i + 1 >= argc) syntax();
      std::string option(argv[i]), value(argv[i+1]);
      if (value.empty() && option != "--seed") err_quit("Option %s requires a nonempty value", option.c_str());
      if (option == "--seed") {
        if (seeded || value.empty() || value.find_first_not_of("0123456789") != std::string::npos)
          err_quit("Seed must be a nonnegative decimal integer, specified once");
        seed = NTL::to_ZZ(value.c_str());
        NTL::SetSeed(seed);
        seeded = true;
      } else if (option == "--output") output = value;
      else if (option == "--helpers") helpers = value;
      else if (option == "--direction") direction = value;
      else if (option == "--decrypt-output") decrypt_output = value;
      else if (option == "--decrypt-helpers") decrypt_helpers = value;
      else syntax();
    }
    if (direction != "encrypt" && direction != "decrypt" && direction != "both") syntax();
    if (direction != "encrypt" && Nk > 8)
      err_quit("Decryption supports only standard AES-128/192/256");
    if (direction != "both" && (!decrypt_output.empty() || !decrypt_helpers.empty()))
      err_quit("--decrypt-output and --decrypt-helpers require --direction both");
    if (output.empty()) output = direction == "decrypt" ? "aes_whitebox_decrypt_tables.cc" : "aes_whitebox_tables.cc";
    if (helpers.empty()) helpers = output + ".helpers.cc";
    output = CanonicalOutput(output);
    helpers = CanonicalOutput(helpers);
    std::vector<std::string> destinations = {output, helpers};
    if (direction == "both") {
      if (decrypt_output.empty())
        decrypt_output = output.substr(0, output.find_last_of('/')+1) + "aes_whitebox_decrypt_tables.cc";
      if (decrypt_helpers.empty()) decrypt_helpers = decrypt_output + ".helpers.cc";
      decrypt_output = CanonicalOutput(decrypt_output);
      decrypt_helpers = CanonicalOutput(decrypt_helpers);
      destinations.push_back(decrypt_output);
      destinations.push_back(decrypt_helpers);
    }
    for (size_t i = 0; i < destinations.size(); ++i)
      for (size_t j = 0; j < i; ++j)
        if (destinations[i] == destinations[j]) err_quit("Generated output paths must differ");
    if (direction != "decrypt") GenerateTables(argv[2], Nk, Nk+6, output, helpers);
    if (direction != "encrypt") {
      // Keep the existing encryption random stream unchanged; a separate seed
      // domain makes decryption reproducible in decrypt-only and both modes.
      if (seeded) {
        std::ostringstream domain;
        domain << "aes-whitebox/decrypt/" << seed;
        const std::string bytes = domain.str();
        NTL::SetSeed(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
      }
      GenerateTables(argv[2], Nk, Nk+6,
                     direction == "decrypt" ? output : decrypt_output,
                     direction == "decrypt" ? helpers : decrypt_helpers, true);
    }
  } catch (const std::exception& error) {
    fprintf(stderr, "Generation failed: %s\n", error.what());
    return 1;
  }
  return 0;
}
