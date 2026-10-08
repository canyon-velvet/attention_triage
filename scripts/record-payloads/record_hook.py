"""Payload recorder: re-records Claude Code hook payloads for tests/fixtures/payloads/.

Saves every Claude Code hook payload verbatim to payloads/. The file name starts
with the receive time in nanoseconds, so arrival order can be checked later.
Never raises, always exits 0.
"""
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    raw = sys.stdin.buffer.read()
    try:
        event = json.loads(raw).get("hook_event_name", "unknown")
    except Exception:
        event = "unparseable"
    out = HERE / "payloads"
    out.mkdir(exist_ok=True)
    (out / f"{time.time_ns()}-{os.getpid()}-{event}.json").write_bytes(raw)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        with open(HERE / "errors.log", "a") as f:
            f.write(traceback.format_exc())
    sys.exit(0)
