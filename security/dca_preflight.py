"""Exit 2 means unavailable, never 'attack passed' or 'key not recovered'."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--output", default="build/dca/preflight.json")
parser.add_argument("--deadpool-python", default="python2")
args = parser.parse_args()
reasons = []
if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64", "i686"):
    reasons.append("The supplied Deadpool/PIN workflow requires a Linux x86/x86_64 execution host.")
for executable in ("Tracer", "daredevil"):
    if not shutil.which(executable):
        reasons.append(executable + " is not available on PATH")
try:
    deadpool = subprocess.run([args.deadpool_python, "-c", "import deadpool_dca"],
                              capture_output=True, timeout=10)
    if deadpool.returncode:
        reasons.append("deadpool_dca cannot be imported using " + args.deadpool_python)
except (OSError, subprocess.TimeoutExpired):
    reasons.append("Deadpool-compatible interpreter unavailable: " + args.deadpool_python)
try:
    docker = subprocess.run(["docker", "info", "--format", "{{.Architecture}}"],
                            capture_output=True, text=True, timeout=10)
    docker_status = docker.stdout.strip() if docker.returncode == 0 else docker.stderr.strip()
except (OSError, subprocess.TimeoutExpired) as error:
    docker_status = str(error)
report = {
    "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    "host": {"system": platform.system(), "machine": platform.machine()},
    "status": "unavailable" if reasons else "ready_for_tracing",
    "reasons": reasons,
    "docker_probe": docker_status,
    "before": {"traces_collected": 0, "key_recovered": None, "traces_to_recovery": None},
    "after": {"traces_collected": 0, "key_recovered": None, "traces_to_recovery": None},
}
path = Path(args.output)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
raise SystemExit(2 if reasons else 0)
