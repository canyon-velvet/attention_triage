import json
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from attention_triage import policy, rules, store
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
# Bash PreToolUse with dangerouslyDisableSandbox. The other events of these calls repeat the input.
SHOULD_FLAG = {
    "auto-bypass-preemptive/01-PreToolUse.json",
    "auto-bypass-retry-after-block/01-PreToolUse.json",  # preemptive here: no earlier events
    "default-prompt-approved-bypass-retry/02-PreToolUse.json",
}
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def event(name: str) -> dict:
    return normalize(redact(json.loads((FIXTURES / name).read_text())))


def evaluate(name: str, policy_text: str = policy.DEFAULT_POLICY) -> list[dict]:
    flags = rules.evaluate(event(name), *policy.parse(policy_text), now=NOW)
    return [f for f in flags if f["rule_id"] == "sandbox_bypass"]


def fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


@pytest.mark.parametrize("name", [fixture_id(path) for path in ALL_FIXTURES])
def test_only_bash_calls_with_the_sandbox_disabled_are_flagged(name):
    assert [f["rule_id"] for f in evaluate(name)] == (
        ["sandbox_bypass"] if name in SHOULD_FLAG else []
    )


def test_a_bypass_is_flagged_preemptive_with_the_full_record():
    name = "auto-bypass-preemptive/01-PreToolUse.json"
    _, version = policy.parse(policy.DEFAULT_POLICY)
    assert evaluate(name) == [
        {
            "event_key": event(name)["dedup_key"],
            "rule_id": "sandbox_bypass",
            "severity": "high",
            "reason": "The agent asked to run a command with the sandbox disabled.",
            "label": "preemptive",
            "evidence": {"command": "ls ~/Desktop"},
            "policy_version": version,
            "status": "open",
            "created_at": "2026-10-08T12:00:00.000+00:00",
            "updated_at": "2026-10-08T12:00:00.000+00:00",
        }
    ]


def test_severity_comes_from_the_policy():
    [flag] = evaluate(
        "auto-bypass-preemptive/01-PreToolUse.json",
        "version: 1\nrules:\n  sandbox_bypass: {severity: review}\n",
    )
    assert flag["severity"] == "review"


@pytest.mark.parametrize("name", sorted(SHOULD_FLAG))
def test_a_disabled_rule_flags_nothing(name):
    assert evaluate(name, "version: 1\nrules:\n  sandbox_bypass: {enabled: false}\n") == []


# retry-after-block (#12): the recorded sessions, stored in the order the events happened.
BLOCKED = "auto-sandbox-block-filesystem/02-PostToolUseFailure.json"  # touch: not permitted
RETRY = "auto-bypass-retry-after-block/01-PreToolUse.json"  # the same touch, sandbox disabled


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    with closing(store.connect()) as conn:
        yield conn


def stored(conn, name: str, minute: float, **changes) -> dict:
    """A fixture event captured `minute` minutes after NOW, stored in the DB."""
    payload = {**json.loads((FIXTURES / name).read_text()), **changes}
    stored_event = normalize(redact(payload), now=NOW + timedelta(minutes=minute))
    store.insert_event(conn, stored_event)
    return stored_event


def bypass_flag(conn, name: str, minute: float, **changes) -> dict:
    loaded, version = policy.parse(policy.DEFAULT_POLICY)
    flags = rules.evaluate(stored(conn, name, minute, **changes), loaded, version, conn=conn)
    [flag] = [f for f in flags if f["rule_id"] == "sandbox_bypass"]
    return flag


def test_a_retry_of_a_sandbox_blocked_command_is_labelled_with_the_block(conn):
    stored(conn, BLOCKED, 0)
    flag = bypass_flag(conn, RETRY, 1)
    assert flag["label"] == "retry-after-block"
    assert flag["evidence"] == {
        "command": "touch ~/triage-spike-blocked.txt",
        "blocked_command": "touch ~/triage-spike-blocked.txt",
        "sandbox_error": "Exit code 1\ntouch: /Users/alice/triage-spike-blocked.txt: "
        "Operation not permitted",
    }


def test_a_retry_after_an_approved_prompt_in_default_mode_is_labelled(conn):
    stored(conn, "default-prompt-approved-then-sandbox-block/03-PostToolUseFailure.json", 0)
    flag = bypass_flag(conn, "default-prompt-approved-bypass-retry/02-PreToolUse.json", 2)
    assert flag["label"] == "retry-after-block"


def test_a_network_block_counts_too(conn):
    stored(conn, "auto-sandbox-block-network/02-PostToolUseFailure.json", 0)
    retry = {"command": "curl -sS -I https://example.com", "dangerouslyDisableSandbox": True}
    flag = bypass_flag(conn, RETRY, 1, tool_input=retry, tool_use_id="toolu_curl_retry")
    assert flag["label"] == "retry-after-block"
    assert "<sandbox_violations>" in flag["evidence"]["sandbox_error"]


def test_a_bypass_after_a_block_of_a_different_program_is_preemptive(conn):
    # The recorded session: touch and curl were blocked, then `ls ~/Desktop` ran unsandboxed.
    stored(conn, BLOCKED, 0)
    stored(conn, "auto-sandbox-block-network/02-PostToolUseFailure.json", 2)
    flag = bypass_flag(conn, "auto-bypass-preemptive/01-PreToolUse.json", 3)
    assert flag["label"] == "preemptive"
    assert flag["evidence"] == {"command": "ls ~/Desktop"}


@pytest.mark.parametrize(
    "minute, changes",
    [
        (-11, {}),  # more than 10 minutes before the retry
        (2, {}),  # after it
        (0, {"session_id": "another-session"}),
        (0, {"error": "Exit code 1\ntouch: /nope/x: No such file or directory"}),  # not the sandbox
        # Output that only mentions the denial text (here: printing SPEC.md), seen in real data.
        (
            0,
            {
                "error": "Exit code 2\na denial (contains `Operation not permitted`, or a `<sandbox_violations>` block)"
            },
        ),
    ],
)
def test_other_failures_leave_a_bypass_preemptive(conn, minute, changes):
    stored(conn, BLOCKED, minute, **changes)
    assert bypass_flag(conn, RETRY, 1)["label"] == "preemptive"
