"""triage-hook: store one Claude Code hook event from stdin. Never raises; always exits 0."""
import json
import sys
import traceback
from contextlib import closing
from datetime import UTC, datetime

from attention_triage import store
from attention_triage.normalize import normalize


def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read())
        with closing(store.connect()) as conn:
            store.insert_event(conn, normalize(payload))
    except Exception:
        log_error()
    sys.exit(0)


def log_error() -> None:
    try:
        store.data_dir().mkdir(parents=True, exist_ok=True)
        with open(store.data_dir() / "hook-errors.log", "a") as log:
            log.write(f"{datetime.now(UTC).isoformat()} {traceback.format_exc()}\n")
    except OSError:
        pass
