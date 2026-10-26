# DCA evaluation

Functional correctness is tested separately from resistance to key extraction.
The DCA scripts are experimental scaffolding; the end-to-end toolchain has not
completed successfully. The user stopped DCA work after tracer startup errors.

The added random nibble encodings and external encodings have not yet been
validated by a completed before/after DCA experiment. A missing tool, failed
tracer, or absent result is **unknown**, never "key recovery failed".

## Comparable targets

```sh
make dca-prepare
```

This builds `build/dca/before/target` from original commit
`6c47af74aef5042c57315e44c6495049c0ff6072` and `build/dca/after/target` from
the working tree. Both use the same `-O1 -g` flags and published NIST AES-128 key
`2b7e151628aed2a6abf7158809cf4f3c`. Both accept one 32-digit plaintext argument
and return one hexadecimal raw AES ciphertext. Preparation verifies both
against a NIST block vector and writes hashes to `build/dca/manifest.json`.

The modified target uses table seed 42. The original generator has no explicit
seed; keep its generated tables, binary hashes, and toolchain alongside results.
The manifest identifies the particular original table instance tested.
The attack surface for the supplied target is the **whole executable, including
external encoding adapters**. This makes ordinary AES inputs and outputs
comparable. A deployment where encodings stay outside the attacker's component
needs a separate experiment with a correspondingly defined attack surface.

## Toolchain

Use a compatible Linux x86/x86_64 execution environment with:

- [Deadpool](https://github.com/SideChannelMarvels/Deadpool/blob/master/README_dca.md),
  with its checkout exposed through `PYTHONPATH` and a compatible Python interpreter;
- [TracerPIN](https://github.com/SideChannelMarvels/Tracer/tree/master/TracerPIN),
  built against Intel PIN and installed as `/usr/local/bin/Tracer`;
- [Daredevil](https://github.com/SideChannelMarvels/Daredevil), with OpenMP support.

Record the exact repository commits, PIN version, compiler version, executable
and table hashes, instrumentation options, filter set, input seed, trace budgets,
and attack model. An ARM host reporting `x86_64` inside an emulated container does
not by itself demonstrate that PIN can instrument a target; run the tracer smoke
test first.

`make dca-preflight` reports native prerequisites, returning 2 when unavailable.
It does not run or classify an attack. For an alternative Deadpool interpreter,
run `python3 security/dca_preflight.py --deadpool-python /path/to/python`.

## Capture and analyze

The helper deliberately requires a fresh output directory to prevent mixing
trace sets. Run it using the interpreter compatible with your pinned Deadpool:

```sh
PYTHONPATH=/opt/dca/Deadpool python2 security/trace_deadpool.py \
  build/dca/before/target --traces 200 --input-seed 20261026 \
  --output build/dca/traces-before-200
PYTHONPATH=/opt/dca/Deadpool python2 security/trace_deadpool.py \
  build/dca/after/target --traces 200 --input-seed 20261026 \
  --output build/dca/traces-after-200
```

The script first smoke-tests the tracer against the NIST block. It then collects
stack byte/word values, non-stack byte/word values, and low address bytes for
byte/word accesses, using Deadpool's filters. Nonempty filter sets are converted
with `bin2daredevil`; each generated configuration is run through Daredevil.
The attack uses the AES first-round S-box model, all key bytes and bits, first
order, top-one guesses, two threads, and a 256 MiB analysis memory budget. The same
plaintext seed is set after tracer initialization for comparable inputs.

Keep `result.json`, raw traces, tool output, and configurations. A successful
Daredevil invocation leaves key recovery unclassified: inspect the top-ranked
bytes and independently verify the assembled key against held-out plaintext and
ciphertext pairs:

```sh
python3 security/verify_recovery.py build/dca/traces-before-200/result.json \
  --candidate <assembled-top-ranked-key> --target build/dca/before/target
```

The verifier checks the target hash and compares eight held-out blocks against
OpenSSL before writing recovery fields. Do not classify a merely high correlation or a known-key rank
hint as verified full-key recovery.

Repeat both targets with matching budgets, for example 200, 500, 1000, and 2000
traces, then refine the first successful budget. Report the smallest **tested**
successful budget and preceding unsuccessful budget, rather than claiming an
exact minimum. A negative result must specify the exhausted budget, filters,
model, seeds, and compiled artifacts. It does not establish resistance to other
DCA models, higher-order attacks, or algebraic attacks.

## Current result

See [dca-baseline.json](dca-baseline.json). Null recovery fields mean no valid
measurement is available. Local PIN errors and the remote runtime-library startup error are recorded;
DCA work was cancelled before measurement. No claim about recovery resistance
can be made from these attempts.
