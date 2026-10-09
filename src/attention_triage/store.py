"""SQLite event store at ~/.attention-triage/triage.db, and the spool that buffers events while
the DB can't be written."""

import fcntl
import json
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Temporary: SPEC §4 reads this from retention_days in policy.yaml (default 7). Deferred until
# the review UI exists (#22).
RETENTION_DAYS = 7

COLUMNS = [
    "agent",
    "session_id",
    "agent_id",
    "event_type",
    "tool_name",
    "tool_use_id",
    "target_kind",
    "target",
    "stated_reason",
    "project_root",
    "cwd",
    "ts",
    "summary",
    "raw",
    "dedup_key",
    "install_scope",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    agent TEXT NOT NULL,
    session_id TEXT,
    agent_id TEXT,
    event_type TEXT,
    tool_name TEXT,
    tool_use_id TEXT,
    target_kind TEXT,
    target TEXT,
    stated_reason TEXT,
    project_root TEXT,
    cwd TEXT,
    ts TEXT NOT NULL,
    summary TEXT NOT NULL,
    raw TEXT NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    install_scope TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS drift (
    hook_event TEXT NOT NULL,
    field TEXT NOT NULL,
    problem TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (hook_event, field, problem)
);
"""


def data_dir() -> Path:
    return Path.home() / ".attention-triage"


def connect() -> sqlite3.Connection:
    """Open the DB in WAL mode with a 2 s busy timeout, creating it if needed."""
    path = data_dir() / "triage.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=2.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    return conn


def insert_event(conn: sqlite3.Connection, event: dict) -> bool:
    """Store a normalized event once. Returns False if its dedup_key is already stored."""
    row = {**event, "summary": json.dumps(event["summary"], ensure_ascii=False)}
    cursor = conn.execute(
        f"INSERT OR IGNORE INTO events ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})",
        [row[column] for column in COLUMNS],
    )
    conn.commit()
    return cursor.rowcount == 1


def record_drift(
    conn: sqlite3.Connection, hook_event: str | None, issues: list[tuple[str, str]], ts: str
) -> None:
    """Remember each (event, field, problem) the first time it is seen, for `triage doctor`."""
    conn.executemany(
        "INSERT OR IGNORE INTO drift (hook_event, field, problem, first_seen) VALUES (?, ?, ?, ?)",
        [(hook_event or "?", field, problem, ts) for field, problem in issues],
    )
    conn.commit()


def purge(conn: sqlite3.Connection, days: int = RETENTION_DAYS) -> None:
    """Delete events captured more than `days` ago. `ts` is always UTC in one ISO layout, so
    comparing the strings compares the times."""
    cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
    conn.execute("DELETE FROM events WHERE ts < ?", [cutoff])
    conn.commit()


def spool_path() -> Path:
    return data_dir() / "spool.jsonl"


@contextmanager
def spool_lock():
    """Hooks run in parallel: without the lock, an event appended while another hook ingests
    could land in a spool that is about to be deleted."""
    data_dir().mkdir(parents=True, exist_ok=True)
    with open(data_dir() / "spool.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def spool(event: dict) -> None:
    """Buffer an event the DB couldn't take; the next successful hook run stores it."""
    with spool_lock(), open(spool_path(), "a", encoding="utf-8") as f:
        # The leading newline ends a record a killed hook left without one, so this event
        # doesn't join that broken line and get skipped with it.
        f.write("\n" + json.dumps(event, ensure_ascii=False) + "\n")


def ingest_spool(conn: sqlite3.Connection) -> None:
    """Store spooled events (dedup makes repeats harmless), then delete the spool. If storing
    fails, the spool stays for the next run."""
    if not spool_path().exists():
        return
    with spool_lock():
        if not spool_path().exists():  # another hook ingested it while we waited
            return
        # Bytes, split only on \n and \r: str.splitlines() would also split an event on U+2028,
        # which json.dumps(ensure_ascii=False) leaves unescaped.
        for line in spool_path().read_bytes().splitlines():
            try:
                event = json.loads(line)
            except ValueError:  # blank, or cut short (even mid-character) by a killed hook:
                continue  # failing on it would wedge every ingest
            insert_event(conn, event)
        spool_path().unlink()
