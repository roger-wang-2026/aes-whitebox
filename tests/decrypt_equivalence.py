"""Independent inverse AES/CBC checks and generator direction compatibility."""
import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import random
import shlex
import sys
import tempfile

from equivalence import ROOT, GEN, PTR, U8, block, buffer, oracle, run, generate


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate_inverse(bits, key, seed, directory, both=False):
    args = [GEN, f"aes{bits}", key.hex(), "--seed", seed,
            "--direction", "both" if both else "decrypt"]
    if both:
        args += ["--output", directory / "aes_whitebox_tables.cc",
                 "--helpers", directory / "external_encodings.cc",
                 "--decrypt-helpers", directory / "decrypt_external_encodings.cc"]
    else:
        args += ["--output", directory / "aes_whitebox_decrypt_tables.cc",
                 "--helpers", directory / "decrypt_external_encodings.cc"]
    run(args)
    return tuple(digest(directory / name) for name in
                 ("aes_whitebox_decrypt_tables.cc", "decrypt_external_encodings.cc"))


def compile_inverse(directory, core_only=False, both=False):
    name = "inverse_core" if core_only else "both" if both else "inverse"
    target = directory / (name + ".dylib")
    args = shlex.split(os.environ.get("CXX", "c++"))
    args += ["-std=c++11", "-O1", "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared"]
    args += shlex.split(os.environ.get("EQUIVALENCE_CXXFLAGS", ""))
    args += ["-I", directory, ROOT / "aes_whitebox_decrypt.cc"]
    if core_only:
        args += ["-DAES_WHITEBOX_CORE_ONLY"]
    else:
        args += [directory / "decrypt_external_encodings.cc"]
    if both:
        args += [ROOT / "aes_whitebox.cc", directory / "external_encodings.cc"]
    run(args + ["-o", target])
    return ctypes.CDLL(str(target))


def decrypt_cbc(lib, iv, data, in_place):
    function = lib.aes_whitebox_decrypt_cbc
    function.argtypes = [PTR, PTR, ctypes.c_size_t, PTR]
    function.restype = ctypes.c_int
    source = buffer(data)
    storage = (U8 * (len(data)+2))(*([0xa5] * (len(data)+2)))
    output = ctypes.cast(ctypes.byref(storage, 1), PTR)
    if in_place:
        ctypes.memmove(output, source, len(data))
    iv_buffer = buffer(iv)
    assert function(iv_buffer, output if in_place else source, len(data), output) == 0
    assert storage[0] == storage[len(data)+1] == 0xa5
    assert bytes(source) == data and bytes(iv_buffer) == iv
    return bytes(storage)[1:len(data)+1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", default="1,2,3")
    parser.add_argument("--blocks", type=int, default=128)
    args = parser.parse_args()
    seeds = args.seeds.split(",")
    if len(seeds) < 2 or len(set(seeds)) != len(seeds) or args.blocks < 1:
        parser.error("use at least two distinct seeds and a positive block count")
    rng = random.Random(20261027)
    blocks = cbc_checks = 0
    with tempfile.TemporaryDirectory(prefix="inverse-", dir=ROOT / "build") as temp:
        base = Path(temp)
        for bits in (128, 192, 256):
            key = bytes(rng.randrange(256) for _ in range(bits // 8))
            ciphertext = bytes(rng.randrange(256) for _ in range(args.blocks*16))
            ciphertext += b"".join(bytes([value])*16 for value in range(256))
            expected = oracle(bits, key, ciphertext, decrypt=True)
            seen = set()
            for index, seed in enumerate(seeds):
                directory = base / f"aes{bits}-seed{seed}"
                directory.mkdir()
                enc_hashes = generate(bits, key, seed, directory)
                inverse_hashes = generate_inverse(bits, key, seed, directory, both=True)
                assert tuple(digest(directory / name) for name in
                             ("aes_whitebox_tables.cc", "external_encodings.cc")) == enc_hashes
                assert inverse_hashes not in seen, "inverse seeds produced identical artifacts"
                seen.add(inverse_hashes)
                standalone = directory / "standalone"
                standalone.mkdir()
                assert generate_inverse(bits, key, seed, standalone) == inverse_hashes
                if index == 0:
                    assert generate_inverse(bits, key, seed, standalone) == inverse_hashes
                lib = compile_inverse(directory, both=True)
                # The independent inverse binary must link without any encryption code.
                inverse = compile_inverse(standalone)
                assert not hasattr(inverse, "aes_whitebox_encrypt_encoded_block")
                assert not hasattr(inverse, "aes_whitebox_encrypt_cbc")
                core = compile_inverse(standalone, core_only=True) if index == 0 else inverse
                if index == 0:
                    assert not hasattr(core, "aes_whitebox_decrypt_encode_input_block")
                    assert not hasattr(core, "aes_whitebox_decrypt_cbc")
                for offset in range(0, len(ciphertext), 16):
                    value = ciphertext[offset:offset+16]
                    encoded = block(inverse, "decrypt_encode_input", value)
                    decoded = block(core, "decrypt_encoded", encoded)
                    actual = block(inverse, "decrypt_decode_output", decoded)
                    assert actual == expected[offset:offset+16], (bits, seed, offset)
                    blocks += 1
                # Also check the independently linked cores coexist in one binary.
                value = ciphertext[:16]
                encrypted = block(lib, "decode_output", block(lib, "encrypt_encoded", block(lib, "encode_input", value)))
                assert encrypted == oracle(bits, key, value)
                actual = block(lib, "decrypt_decode_output", block(lib, "decrypt_encoded", block(lib, "decrypt_encode_input", encrypted)))
                assert actual == value
                for iv in (bytes(16), bytes(rng.randrange(256) for _ in range(16))):
                    for length in (0, 16, 32, 48, 64, 256, 1024):
                        value = ciphertext[:length]
                        expected_cbc = oracle(bits, key, value, "cbc", iv, decrypt=True)
                        for in_place in (False, True):
                            for binary in (lib, inverse):
                                assert decrypt_cbc(binary, iv, value, in_place) == expected_cbc
                                cbc_checks += 1
                print(f"AES-{bits}, seed {seed}: inverse core/CBC OpenSSL equivalence and direction compatibility passed", flush=True)
    print(f"Inverse equivalence: {blocks} blocks, {cbc_checks} CBC checks; isolated/both/core-only builds and seed replay passed")


if __name__ == "__main__":
    main()
