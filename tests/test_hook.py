import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from attention_triage import store
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
HOOK = Path(sys.executable).parent / "triage-hook"  # the installed console script


def run_hook(home: Path, stdin: bytes) -> int:
    env = {**os.environ, "HOME": str(home)}
    return subprocess.run([HOOK], input=stdin, env=env, timeout=10).returncode


def rows(home: Path) -> list[sqlite3.Row]:
    db = home / ".attention-triage" / "triage.db"
    if not db.exists():
        return []
    with closing(sqlite3.connect(db)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM events").fetchall()


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_each_fixture_is_stored_exactly_once(tmp_path, path):
    assert run_hook(tmp_path, path.read_bytes()) == 0
    assert len(rows(tmp_path)) == 1
    assert run_hook(tmp_path, path.read_bytes()) == 0
    assert len(rows(tmp_path)) == 1


def test_all_fixtures_get_distinct_rows(tmp_path):
    for path in ALL_FIXTURES:
        run_hook(tmp_path, path.read_bytes())
    assert len(rows(tmp_path)) == len(ALL_FIXTURES)


def test_stored_row_matches_the_normalized_event(tmp_path):
    path = FIXTURES / "auto-sandbox-block-filesystem" / "02-PostToolUseFailure.json"
    run_hook(tmp_path, path.read_bytes())
    [row] = rows(tmp_path)
    expected = normalize(redact(json.loads(path.read_text())))
    for column in store.COLUMNS:
        if column == "summary":
            assert json.loads(row[column]) == expected[column]
        elif column != "ts":
            assert row[column] == expected[column], column


def test_lone_surrogate_from_a_cut_emoji_is_still_stored(tmp_path):
    path = FIXTURES / "auto-sandbox-block-filesystem" / "01-PreToolUse.json"
    stdin = path.read_text().replace("touch ~/triage-spike-blocked.txt", "echo \\ud83d").encode()
    assert run_hook(tmp_path, stdin) == 0
    [row] = rows(tmp_path)
    assert row["target"] == "echo ?"


def test_db_uses_wal_and_a_two_second_busy_timeout(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with closing(store.connect()) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 2000


@pytest.mark.parametrize("stdin", [b"not json", b"[1, 2]", b""])
def test_bad_stdin_exits_0_stores_nothing_and_logs(tmp_path, stdin):
    assert run_hook(tmp_path, stdin) == 0
    assert rows(tmp_path) == []
    assert (tmp_path / ".attention-triage" / "hook-errors.log").read_text()


def spool_lines(home: Path) -> list[str]:
    spool = home / ".attention-triage" / "spool.jsonl"
    return spool.read_text().splitlines() if spool.exists() else []


def make_db_unavailable(home: Path) -> Path:
    """A directory where triage.db should be: sqlite3 can't open it, like a broken DB."""
    db = home / ".attention-triage" / "triage.db"
    db.mkdir(parents=True)
    return db


def test_db_unavailable_spools_the_event_logs_and_exits_0(tmp_path):
    make_db_unavailable(tmp_path)
    path = FIXTURES / "auto-webfetch" / "01-PreToolUse.json"
    assert run_hook(tmp_path, path.read_bytes()) == 0
    [line] = spool_lines(tmp_path)
    expected = normalize(redact(json.loads(path.read_text())))
    assert json.loads(line)["dedup_key"] == expected["dedup_key"]
    assert "OperationalError" in (tmp_path / ".attention-triage" / "hook-errors.log").read_text()


def test_next_successful_run_ingests_the_spool_without_duplicates(tmp_path):
    spooled = (FIXTURES / "auto-webfetch" / "01-PreToolUse.json").read_bytes()
    db = make_db_unavailable(tmp_path)
    run_hook(tmp_path, spooled)
    run_hook(tmp_path, spooled)  # delivered twice while the DB was down
    db.rmdir()
    run_hook(tmp_path, (FIXTURES / "auto-webfetch" / "02-PostToolUse.json").read_bytes())
    assert len(rows(tmp_path)) == 2 and spool_lines(tmp_path) == []
    run_hook(tmp_path, spooled)
    assert len(rows(tmp_path)) == 2


def test_a_spool_line_cut_short_is_skipped_not_fatal(tmp_path):
    db = make_db_unavailable(tmp_path)
    run_hook(tmp_path, (FIXTURES / "auto-webfetch" / "01-PreToolUse.json").read_bytes())
    db.rmdir()
    spool = tmp_path / ".attention-triage" / "spool.jsonl"
    spool.write_text('{"agent": "claude-co\n' + spool.read_text())  # a hook killed mid-write
    run_hook(tmp_path, (FIXTURES / "auto-webfetch" / "02-PostToolUse.json").read_bytes())
    assert len(rows(tmp_path)) == 2 and spool_lines(tmp_path) == []


def test_parallel_hooks_spool_and_ingest_every_event(tmp_path):
    db = make_db_unavailable(tmp_path)
    payload = json.loads((FIXTURES / "auto-webfetch" / "01-PreToolUse.json").read_text())
    env = {**os.environ, "HOME": str(tmp_path)}
    hooks = []
    for i in range(20):
        hook = subprocess.Popen([HOOK], stdin=subprocess.PIPE, env=env)
        hook.stdin.write(json.dumps({**payload, "tool_use_id": f"toolu_{i}"}).encode())
        hook.stdin.close()
        hooks.append(hook)
    assert all(hook.wait(timeout=10) == 0 for hook in hooks)
    assert len(spool_lines(tmp_path)) == 20
    db.rmdir()
    run_hook(tmp_path, (FIXTURES / "auto-webfetch" / "02-PostToolUse.json").read_bytes())
    assert len(rows(tmp_path)) == 21 and spool_lines(tmp_path) == []
