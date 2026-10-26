"""Build comparable DCA oracles from the original commit and working tree."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "6c47af74aef5042c57315e44c6495049c0ff6072"
KEY = "2b7e151628aed2a6abf7158809cf4f3c"  # published NIST test key
PLAIN = "6bc1bee22e409f96e93d7e117393172a"
EXPECTED = "3ad77bb40d7a3660a89ecaf32466ef97"


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    directory = ROOT / "build/dca"
    before = directory / "before"
    after = directory / "after"
    before.mkdir(parents=True, exist_ok=True)
    after.mkdir(parents=True, exist_ok=True)
    for name in ("aes_whitebox.cc", "aes_whitebox.h", "aes_whitebox_compiler.cc", "aes_private.h"):
        source = run(["git", "show", f"{BASELINE}:{name}"], cwd=ROOT, capture_output=True).stdout
        (before / name).write_bytes(source)
    compiler = shlex.split(os.environ.get("CXX", "c++"))
    flags = ["-std=c++11", "-O1", "-g"]
    includes, libraries = [], []
    if shutil.which("brew"):
        for library in ("ntl", "gmp"):
            prefix = run(["brew", "--prefix", library], capture_output=True, text=True).stdout.strip()
            includes += ["-I" + prefix + "/include"]
            libraries += ["-L" + prefix + "/lib"]
    run(compiler + flags + includes + [before / "aes_whitebox_compiler.cc"] + libraries
        + ["-lntl", "-lgmp", "-pthread", "-o", before / "compiler"])
    run([before / "compiler", "aes128", KEY], cwd=before)
    run([ROOT / "build/aes_whitebox_compiler", "aes128", KEY, "--seed", "42",
         "--output", after / "aes_whitebox_tables.cc", "--helpers", after / "external_encodings.cc"])
    driver = ROOT / "security/dca_target.cc"
    run(compiler + flags + ["-DAES_DCA_LEGACY", "-I", before, "-I", ROOT,
                            driver, "-o", before / "target"])
    run(compiler + flags + ["-I", after, "-I", ROOT, driver, ROOT / "aes_whitebox.cc",
                            after / "external_encodings.cc", "-o", after / "target"])
    for target in (before / "target", after / "target"):
        result = run([target, PLAIN], capture_output=True, text=True).stdout.strip()
        assert result == EXPECTED, (target, result)
    manifest = {
        "baseline_commit": BASELINE,
        "key": KEY,
        "after_seed": "42",
        "before_seed": None,
        "before_seed_note": "Original generator has no seed option; retain tables and binary hashes.",
        "host": {"system": platform.system(), "machine": platform.machine()},
        "compile_flags": flags,
        "scope": "whole executable including input/output encoding adapters",
        "artifacts": {},
    }
    for variant in ("before", "after"):
        folder = directory / variant
        manifest["artifacts"][variant] = {
            name: sha(folder / name) for name in ("target", "aes_whitebox_tables.cc")}
    manifest["working_sources"] = {name: sha(ROOT / name) for name in
        ("aes_whitebox.cc", "aes_whitebox_compiler.cc", "aes_whitebox.h", "aes_private.h", "hex.h")}
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("DCA targets built and checked against NIST AES-128 block; manifest:", directory / "manifest.json")


if __name__ == "__main__":
    main()
