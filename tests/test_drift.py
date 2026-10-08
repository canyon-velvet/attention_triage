import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from test_hook import ALL_FIXTURES, rows, run_hook

from attention_triage.normalize import check_shape, normalize

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
BASH_CALL = FIXTURES / "auto-sandbox-block-filesystem" / "01-PreToolUse.json"


def bash_call(**changes) -> dict:
    payload = json.loads(BASH_CALL.read_text())
    payload.update(changes)
    return {key: value for key, value in payload.items() if value is not ...}


def drift_rows(home: Path) -> list[tuple]:
    with closing(sqlite3.connect(home / ".attention-triage" / "triage.db")) as conn:
        return conn.execute("SELECT hook_event, field, problem, first_seen FROM drift").fetchall()


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_recorded_payloads_have_no_drift(path):
    assert check_shape(json.loads(path.read_text())) == []


def test_missing_and_mistyped_fields_are_reported():
    assert check_shape(bash_call(tool_use_id=...)) == [("tool_use_id", "missing")]
    assert check_shape(bash_call(cwd={"path": "/x"})) == [("cwd", "type")]
    assert check_shape(bash_call(tool_input={"cmd": "ls"})) == [("tool_input.command", "missing")]
    assert check_shape({"session_id": "s"}) == [("hook_event_name", "missing")]


def test_mistyped_fields_normalize_to_none():
    event = normalize(
        bash_call(cwd=["/x"], tool_input={"command": ["ls"]}, hook_event_name=["PreToolUse"])
    )
    assert event["cwd"] is None and event["project_root"] is None
    assert event["target"] is None and event["event_type"] is None


def test_hook_stores_the_event_and_records_drift_once(tmp_path):
    assert run_hook(tmp_path, json.dumps(bash_call(tool_use_id=...)).encode()) == 0
    assert len(rows(tmp_path)) == 1
    [(event, field, problem, first_seen)] = drift_rows(tmp_path)
    assert (event, field, problem) == ("PreToolUse", "tool_use_id", "missing")

    run_hook(tmp_path, json.dumps(bash_call(tool_use_id=..., session_id="other")).encode())
    assert len(rows(tmp_path)) == 2
    assert drift_rows(tmp_path) == [("PreToolUse", "tool_use_id", "missing", first_seen)]


@pytest.mark.parametrize("bad_event_name", [..., {"name": "x"}])
def test_events_of_one_call_without_a_usable_event_name_are_all_stored(tmp_path, bad_event_name):
    for name in ("01-PreToolUse.json", "02-PostToolUseFailure.json"):
        payload = json.loads((FIXTURES / "auto-sandbox-block-filesystem" / name).read_text())
        payload["hook_event_name"] = bad_event_name
        run_hook(tmp_path, json.dumps({k: v for k, v in payload.items() if v is not ...}).encode())
    assert len(rows(tmp_path)) == 2


def test_mistyped_payload_is_still_stored(tmp_path):
    payload = bash_call(cwd={"path": "/x"}, tool_input={"command": ["ls"]})
    assert run_hook(tmp_path, json.dumps(payload).encode()) == 0
    assert len(rows(tmp_path)) == 1
    assert {row[1] for row in drift_rows(tmp_path)} == {"cwd", "tool_input.command"}
