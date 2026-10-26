"""Verify an assembled DCA top-ranked key on held-out inputs and record it."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("result", type=Path)
parser.add_argument("--candidate", required=True, help="assembled 16-byte top-ranked key in hex")
parser.add_argument("--target", required=True, type=Path)
args = parser.parse_args()
try:
    key = bytes.fromhex(args.candidate)
except ValueError:
    parser.error("candidate must be hexadecimal")
if len(key) != 16:
    parser.error("candidate must contain exactly 16 bytes")
report = json.loads(args.result.read_text())
if report["status"] != "analysis_complete_requires_key_verification":
    parser.error("only a completed, unclassified analysis can be verified")
if hashlib.sha256(args.target.read_bytes()).hexdigest() != report["target_sha256"]:
    parser.error("target hash differs from the traced executable")
rng = random.Random(0xDCA2026)  # independent of the trace input seed
held_out = bytes(rng.randrange(256) for _ in range(16 * 8))
actual = b""
for offset in range(0, len(held_out), 16):
    output = subprocess.check_output([str(args.target.resolve()), held_out[offset:offset+16].hex()])
    actual += bytes.fromhex(output.decode().strip())
expected = subprocess.check_output(["openssl", "enc", "-aes-128-ecb", "-K", key.hex(),
                                    "-nopad", "-nosalt"], input=held_out)
recovered = actual == expected
report.update({"key_recovered": recovered, "verified_candidate": key.hex(),
               "verification_blocks": 8, "status": "candidate_verified" if recovered else "candidate_rejected",
               "traces_to_recovery": report["traces_collected"] if recovered else None,
               "trace_count_note": "tested budget, not an exact minimum"})
args.result.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
raise SystemExit(0 if recovered else 1)
