#!/usr/bin/env python2
"""Run with the interpreter supported by the pinned Deadpool checkout.

Collect a fresh trace set, then produce Daredevil configurations and logs.
Key recovery remains unclassified until the top-ranked key is independently
verified; a successful process exit alone never means key recovery.
"""
from __future__ import print_function
import argparse
import glob
import hashlib
import json
import os
import random
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("target")
parser.add_argument("--traces", type=int, default=200)
parser.add_argument("--input-seed", type=int, default=20261026)
parser.add_argument("--memory", default="256M")
parser.add_argument("--threads", type=int, default=2)
parser.add_argument("--output", required=True)
parser.add_argument("--tracer", default="/usr/local/bin/Tracer")
parser.add_argument("--daredevil", default="daredevil")
args = parser.parse_args()
if args.traces < 1:
    parser.error("--traces must be positive")
target = os.path.abspath(args.target)
output = os.path.abspath(args.output)
if os.path.exists(output):
    parser.error("--output must be a new directory, to avoid mixing trace sets")
os.makedirs(output)
os.chdir(output)
report = {
    "target_sha256": hashlib.sha256(open(target, "rb").read()).hexdigest(),
    "requested_traces": args.traces,
    "analysis_memory": args.memory,
    "analysis_threads": args.threads,
    "input_seed": args.input_seed,
    "scope": "whole executable, including external adapters when linked",
    "traces_collected": 0,
    "key_recovered": None,
    "traces_to_recovery": None,
    "status": "not_started",
}
exit_code = 0
try:
    import deadpool_dca as dca
    dca.tracerpin_exec = args.tracer
    filters = [dca.DefaultFilters.stack_w1, dca.DefaultFilters.stack_w4,
               dca.DefaultFilters.mem_data_rw1, dca.DefaultFilters.mem_data_rw4,
               dca.DefaultFilters.mem_addr1_rw1, dca.DefaultFilters.mem_addr1_rw4]
    with open("smoke.stdout", "wb") as stdout, open("smoke.stderr", "wb") as stderr:
        code = subprocess.call([args.tracer, "-q", "1", "-b", "0", "-c", "0", "-i", "0",
                                "-f", "2", "-o", "smoke.trace", "--", target,
                                "6bc1bee22e409f96e93d7e117393172a"], stdout=stdout, stderr=stderr)
    if code:
        raise RuntimeError("Tracer smoke test failed (exit %s); see smoke.stdout and smoke.stderr" % code)
    if open("smoke.stdout", "rb").read().strip() != b"3ad77bb40d7a3660a89ecaf32466ef97":
        raise RuntimeError("Tracer did not return the expected AES ciphertext; see smoke.stdout and smoke.stderr")
    tracer = dca.TracerPIN(target, filters=filters, record_info=False,
                           stack_range="0x700000000000-0x800000000000")
    # Seed after constructing Tracer, so its temporary-name randomness does not
    # change the plaintext sequence shared by the before and after experiments.
    random.seed(args.input_seed)
    tracer.run(args.traces)
    available = []
    for filtr in filters:
        files = glob.glob("trace_%s_*.bin" % filtr.keyword)
        if len(files) == args.traces and all(os.path.getsize(path) > 0 for path in files):
            available.append(filtr)
    if not available:
        raise RuntimeError("no nonempty trace set was collected")
    report["filters"] = [filtr.keyword for filtr in available]
    dca.bin2daredevil(keywords=available, delete_bin=False,
                    config={"correct_key": "0x2b7e151628aed2a6abf7158809cf4f3c",
                            "threads": str(args.threads), "memory": args.memory, "top": "1"})
    logs = []
    for config in sorted(glob.glob("*.config")):
        name = config + ".log"
        with open(name, "wb") as log:
            subprocess.check_call([args.daredevil, "-c", config], stdout=log, stderr=subprocess.STDOUT)
        logs.append(name)
    report["status"] = "analysis_complete_requires_key_verification"
    report["logs"] = logs
except Exception as error:
    report["status"] = "tool_error"
    report["error"] = str(error)
    exit_code = 2
finally:
    report["traces_collected"] = len(glob.glob("trace_stack_w1_*.bin"))
    with open("result.json", "w") as result:
        json.dump(report, result, indent=2)
        result.write("\n")
    print(json.dumps(report, indent=2))
sys.exit(exit_code)
