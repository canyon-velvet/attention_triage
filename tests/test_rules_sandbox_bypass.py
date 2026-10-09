import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from attention_triage import policy, rules
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
# Bash PreToolUse with dangerouslyDisableSandbox. The other events of these calls repeat the input.
SHOULD_FLAG = {
    "auto-bypass-preemptive/01-PreToolUse.json",
    "auto-bypass-retry-after-block/01-PreToolUse.json",  # labelled preemptive until #12
    "default-prompt-approved-bypass-retry/02-PreToolUse.json",
}
NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def event(name: str) -> dict:
    return normalize(redact(json.loads((FIXTURES / name).read_text())))


def evaluate(name: str, policy_text: str = policy.DEFAULT_POLICY) -> list[dict]:
    return rules.evaluate(event(name), *policy.parse(policy_text), now=NOW)


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
