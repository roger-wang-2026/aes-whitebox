"""Exercise CLI rejection and atomic-file failure paths without real keys."""
from pathlib import Path
import resource
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "build/aes_whitebox_compiler"
TEST = ROOT / "build/aes128/aes_tests"
KEY = "00" * 16


def reject(args, **kwargs):
    result = subprocess.run([str(x) for x in args], capture_output=True, **kwargs)
    assert result.returncode > 0, (args, result.returncode, result.stderr)
    assert result.stderr, args
    return result


with tempfile.TemporaryDirectory(prefix="robustness-", dir=ROOT / "build") as temp:
    directory = Path(temp)
    table = directory / "tables.cc"
    helper = directory / "helpers.cc"
    options = ["--seed", "42", "--output", table, "--helpers", helper]
    for key in ["", "00", "gg" * 16, "0g" + KEY[2:], "+1" + KEY[2:], " 1" + KEY[2:]]:
        reject([GEN, "aes128", key, *options])
        assert not table.exists() and not helper.exists()
    for seed in ["", "-1", "0x12", "1x"]:
        reject([GEN, "aes128", KEY, "--seed", seed])
    for option in ("--output", "--helpers", "--decrypt-output", "--decrypt-helpers"):
        reject([GEN, "aes128", KEY, *options, option, ""])
    for direction in ("", "invalid"):
        reject([GEN, "aes128", KEY, *options, "--direction", direction])
    reject([GEN, "aes512", "00"*64, *options, "--direction", "decrypt"])
    reject([GEN, "aes128", KEY, *options, "--decrypt-output", table])
    reject([GEN, "aes128", KEY, *options, "--direction", "both", "--decrypt-output", table])
    reject([GEN, "aes128", KEY, *options, "--direction", "both", "--decrypt-helpers", helper])
    assert not table.exists() and not helper.exists()
    reject([GEN])
    reject([GEN, "aes128", KEY, "--output", directory / "missing/tables.cc"])
    reject([GEN, "aes128", KEY, "--output", table, "--helpers", table])
    reject([GEN, "aes128", KEY, "--output", table, "--helpers", str(directory) + "/./tables.cc"])
    for args in [[], ["cfb"], ["cfb", "00" * 64, "00" * 16],
                 ["cfb", "0g" * 64, "00" * 16, "00" * 64],
                 ["unknown", "00" * 64, "00" * 16, "00" * 64]]:
        reject([TEST, *args])
    subprocess.run([str(x) for x in [GEN, "aes128", KEY, *options]], check=True)
    table_size = table.stat().st_size
    table.write_text("old tables")
    helper.write_text("old helpers")

    def limit_output():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))

    reject([GEN, "aes128", KEY, *options], preexec_fn=limit_output)
    assert table.read_text() == "old tables"
    assert helper.read_text() == "old helpers"
    assert not list(directory.glob("*.tmp.*"))
    # fclose may report a delayed buffered write failure even when fprintf passed.
    def limit_close():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (table_size - 1, table_size - 1))
    result = reject([GEN, "aes128", KEY, *options], preexec_fn=limit_close)
    assert b"closing output failed" in result.stderr, result.stderr
    assert table.read_text() == "old tables"
    assert helper.read_text() == "old helpers"
    # A failed rename must preserve the destination directory and remove temps.
    target_dir = directory / "directory"
    target_dir.mkdir()
    reject([GEN, "aes128", KEY, "--seed", "42", "--output", table,
            "--helpers", target_dir])
    assert table.read_text() == "old tables"
    assert target_dir.is_dir()
    assert not list(directory.glob("*.tmp.*"))
print("Robustness: invalid CLI/hex, failed create/write/rename, destination preservation passed")
