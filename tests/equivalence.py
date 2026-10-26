"""Independent OpenSSL oracle, reproducible seeds, and external-encoding contract."""
import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import random
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "build/aes_whitebox_compiler"
U8 = ctypes.c_uint8
PTR = ctypes.POINTER(U8)


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def buffer(data):
    return (U8 * len(data)).from_buffer_copy(data)


def oracle(bits, key, data, mode="ecb", iv=None):
    args = ["openssl", "enc", f"-aes-{bits}-{mode}", "-K", key.hex(), "-nopad", "-nosalt"]
    if iv is not None:
        args += ["-iv", iv.hex()]
    return run(args, input=data, capture_output=True).stdout


def compile_library(directory, core_only=False):
    target = directory / ("core.dylib" if core_only else "whitebox.dylib")
    args = shlex.split(os.environ.get("CXX", "c++"))
    args += ["-std=c++11", "-O1", "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared"]
    args += shlex.split(os.environ.get("EQUIVALENCE_CXXFLAGS", ""))
    args += ["-I", directory, ROOT / "aes_whitebox.cc"]
    if core_only:
        args += ["-DAES_WHITEBOX_CORE_ONLY"]
    else:
        args += [directory / "external_encodings.cc"]
    args += ["-o", target]
    run(args)
    return ctypes.CDLL(str(target))


def block(lib, name, data):
    function = getattr(lib, "aes_whitebox_" + name + "_block")
    function.argtypes = [PTR, PTR]
    function.restype = None
    output = (U8 * 16)()
    function(buffer(data), output)
    return bytes(output)


def mode_call(lib, operation, mode, iv, data):
    function = getattr(lib, f"aes_whitebox_{operation}_{mode}")
    function.argtypes = [PTR, PTR, ctypes.c_size_t, PTR]
    function.restype = None
    output = buffer(data)  # exact in-place call
    function(buffer(iv), output, len(data), output)
    return bytes(output)


def cbc_call(lib, iv, data, in_place):
    function = lib.aes_whitebox_encrypt_cbc
    function.argtypes = [PTR, PTR, ctypes.c_size_t, PTR]
    function.restype = ctypes.c_int
    source = buffer(data)
    output = source if in_place else (U8 * len(data))()
    iv_buffer = buffer(iv)
    assert function(iv_buffer, source, len(data), output) == 0
    assert bytes(iv_buffer) == iv
    if not in_place:
        assert bytes(source) == data
    return bytes(output)


def generate(bits, key, seed, directory):
    run([GEN, f"aes{bits}", key.hex(), "--seed", seed,
         "--output", directory / "aes_whitebox_tables.cc",
         "--helpers", directory / "external_encodings.cc"])
    return tuple(hashlib.sha256((directory / name).read_bytes()).hexdigest()
                 for name in ("aes_whitebox_tables.cc", "external_encodings.cc"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", default="1,2,3")
    parser.add_argument("--blocks", type=int, default=128)
    args = parser.parse_args()
    seeds = args.seeds.split(",")
    if len(seeds) < 2 or len(set(seeds)) != len(seeds) or args.blocks < 1:
        parser.error("use at least two distinct seeds and a positive block count")
    if not shutil.which("openssl"):
        parser.error("openssl is required as an independent AES oracle")
    rng = random.Random(20261026)
    total_blocks = 0
    total_modes = 0
    total_cbc = 0
    with tempfile.TemporaryDirectory(prefix="equivalence-", dir=ROOT / "build") as temp:
        base = Path(temp)
        for bits in (128, 192, 256):
            key = bytes(rng.randrange(256) for _ in range(bits // 8))
            data = bytes(rng.randrange(256) for _ in range(args.blocks * 16))
            # All possible byte values cross each boundary, in addition to random inputs.
            data += b"".join(bytes([value])*16 for value in range(256))
            expected = oracle(bits, key, data)
            hashes = set()
            for index, seed in enumerate(seeds):
                directory = base / f"aes{bits}-seed{seed}"
                directory.mkdir()
                digest = generate(bits, key, seed, directory)
                assert digest not in hashes, "different seeds produced identical artifacts"
                hashes.add(digest)
                if index == 0:
                    assert generate(bits, key, seed, directory) == digest, "seed replay changed artifacts"
                lib = compile_library(directory)
                core = compile_library(directory, core_only=True) if index == 0 else lib
                if index == 0:
                    assert not hasattr(core, "aes_whitebox_encode_input_block")
                    assert not hasattr(core, "aes_whitebox_encrypt_ctr")
                    assert not hasattr(core, "aes_whitebox_encrypt_cbc")
                for offset in range(0, len(data), 16):
                    plain = data[offset:offset+16]
                    encoded = block(lib, "encode_input", plain)
                    encrypted = block(core, "encrypt_encoded", encoded)
                    actual = block(lib, "decode_output", encrypted)
                    assert actual == expected[offset:offset+16], (bits, seed, offset)
                    total_blocks += 1
                for mode in ("cfb", "ofb", "ctr"):
                    for iv in (bytes(rng.randrange(256) for _ in range(16)),
                               bytes.fromhex("0102030405060708090a0b0c0d0effff")):
                        for length in (0, 1, 15, 16, 17, 31, 32, 33, 257):
                            plain = data[:length]
                            expected_mode = oracle(bits, key, plain, mode, iv)
                            actual = mode_call(lib, "encrypt", mode, iv, plain)
                            assert actual == expected_mode, (bits, seed, mode, length, "encrypt")
                            assert mode_call(lib, "decrypt", mode, iv, actual) == plain
                            total_modes += 2
                # CBC has a separate status-returning, full-block-only API.
                for iv in (bytes(16), bytes(rng.randrange(256) for _ in range(16))):
                    for length in (0, 16, 32, 48, 64, 256, 1024):
                        plain = data[:length]
                        expected_cbc = oracle(bits, key, plain, "cbc", iv)
                        for in_place in (False, True):
                            assert cbc_call(lib, iv, plain, in_place) == expected_cbc, (bits, seed, length, in_place)
                            total_cbc += 1
                print(f"AES-{bits}, seed {seed}: encoded core, modes, CBC, OpenSSL equivalence passed", flush=True)
    print(f"Equivalence: {total_blocks} blocks, {total_modes} existing-mode checks, {total_cbc} CBC checks; seed replay and core/helper separation passed")


if __name__ == "__main__":
    main()
