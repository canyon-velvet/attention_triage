"""triage-hook: store one Claude Code hook event from stdin. Never raises; always exits 0."""

import json
import sys
import traceback
from contextlib import closing
from datetime import UTC, datetime

from attention_triage import store
from attention_triage.normalize import check_shape, normalize, text
from attention_triage.redact import redact


def main() -> None:
    try:
        payload = read_payload()
        event = normalize(redact(payload))
        with closing(store.connect()) as conn:
            store.insert_event(conn, event)
            if issues := check_shape(payload):
                store.record_drift(conn, text(payload.get("hook_event_name")), issues, event["ts"])
    except Exception:
        log_error()
    sys.exit(0)


def read_payload():
    payload = json.loads(sys.stdin.buffer.read())
    # A lone UTF-16 surrogate (e.g. an emoji cut in half) can't be stored in SQLite; replace it.
    return json.loads(json.dumps(payload, ensure_ascii=False).encode("utf-8", "replace"))


def log_error() -> None:
    try:
        store.data_dir().mkdir(parents=True, exist_ok=True)
        with open(store.data_dir() / "hook-errors.log", "a") as log:
            log.write(f"{datetime.now(UTC).isoformat()} {traceback.format_exc()}\n")
    except OSError:
        pass
