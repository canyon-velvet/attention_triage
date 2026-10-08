"""SQLite event store at ~/.attention-triage/triage.db."""

import json
import sqlite3
from pathlib import Path

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
