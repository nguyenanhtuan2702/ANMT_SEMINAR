"""Run the complete pytest suite with durable logs and a bounded subprocess.

Windows error dialogs are disabled for this runner and its child only, so a
native-extension crash yields an exit code/log instead of an unattended dialog.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="final")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-z0-9_]+", args.label) or args.timeout <= 0:
        parser.error("Use a simple lowercase label and a positive timeout.")
    if os.name == "nt":
        ctypes.windll.kernel32.SetErrorMode(3)
    folder = Path("reports/testing_optimization")
    folder.mkdir(parents=True, exist_ok=True)
    log = folder/f"pytest_{args.label}.log"
    command = [sys.executable, "-m", "pytest", "-vv", "--continue-on-collection-errors",
               f"--junitxml={folder/f'pytest_{args.label}.xml'}"]
    with log.open("wb") as stream:
        child = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                                 env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print(f"pytest PID {child.pid}; live log: {log}", flush=True)
        try:
            code = child.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            code = 124
    result = {"command": command, "exit_code": code, "log": log.as_posix()}
    (folder/f"pytest_{args.label}_run.json").write_bytes((json.dumps(result, indent=2)+"\n").encode("utf-8"))
    print(json.dumps(result))
    print(log.read_text(encoding="utf-8", errors="replace")[-4000:])
    raise SystemExit(code)


if __name__ == "__main__":
    main()
