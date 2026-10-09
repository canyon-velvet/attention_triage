import json
from pathlib import Path

import pytest

from attention_triage import policy, rules
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
# WebFetch of example.com. Its PostToolUse repeats the input.
SHOULD_FLAG = {"auto-webfetch/01-PreToolUse.json"}


def call(tool: str, target: str) -> dict:
    key = "url" if tool == "WebFetch" else "command"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "tool_use_id": "t1",
        "cwd": "/Users/alice/Dev/proj",
        "tool_name": tool,
        "tool_input": {key: target},
    }
    return normalize(payload)


def r4(event: dict, policy_text: str = policy.DEFAULT_POLICY) -> list[dict]:
    flags = rules.evaluate(event, *policy.parse(policy_text))
    return [f for f in flags if f["rule_id"] == "unlisted_domain"]


def fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


@pytest.mark.parametrize("name", [fixture_id(path) for path in ALL_FIXTURES])
def test_only_calls_reaching_unlisted_hosts_are_flagged(name):
    event = normalize(redact(json.loads((FIXTURES / name).read_text())))
    assert len(r4(event)) == (1 if name in SHOULD_FLAG else 0)


def test_a_webfetch_flag_is_unlabelled_with_review_severity():
    [flag] = r4(call("WebFetch", "https://example.com/page"))
    assert flag["severity"] == "review"
    assert flag["reason"] == "The agent asked to fetch from a host that isn't in allowed_domains."
    assert flag["label"] == ""
    assert flag["evidence"] == {"hosts": ["example.com"]}


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/canyon-velvet",
        "HTTPS://GitHub.COM:443/x",
        "https://user:secret@github.com/x",
        "https://github.com./x",
        "https://raw.githubusercontent.com/a/b",
        "https://a.b.githubusercontent.com/x",
        "https://pypi.org/simple/",
    ],
)
def test_listed_hosts_are_allowed(url):
    assert r4(call("WebFetch", url)) == []


@pytest.mark.parametrize(
    "url, host",
    [
        ("https://api.github.com/x", "api.github.com"),  # an exact entry doesn't cover subdomains
        ("https://githubusercontent.com/x", "githubusercontent.com"),  # `*.` needs a subdomain
        ("https://evilgithubusercontent.com/x", "evilgithubusercontent.com"),
        (
            "https://raw.githubusercontent.com.evil.example/x",
            "raw.githubusercontent.com.evil.example",
        ),
        ("https://github.com@evil.example/x", "evil.example"),  # user info, not the host
        ("https://evil.example\\@github.com/", "evil.example"),  # WebFetch reads `\` as `/`
        ("https://evil.example\\.githubusercontent.com/", "evil.example"),
        ("https://bob:[REDACTED]@evil.example/r.git", "evil.example"),  # a redacted password
        ("https://a[b]@evil.example/", "evil.example"),
        ("https://u／x@evil.example/", "evil.example"),  # a fullwidth `/` in the user name
    ],
)
def test_look_alike_hosts_are_flagged(url, host):
    [flag] = r4(call("WebFetch", url))
    assert flag["evidence"] == {"hosts": [host]}


def test_a_malformed_url_is_flagged_not_skipped():
    [flag] = r4(call("WebFetch", "http://[::1/x"))
    assert flag["evidence"] == {"hosts": ["::1"]}


def test_allowed_domains_replace_the_defaults():
    allowed = "version: 1\nrules:\n  unlisted_domain: {allowed_domains: ['*.example']}\n"
    assert r4(call("WebFetch", "https://docs.example/x"), allowed) == []
    assert len(r4(call("WebFetch", "https://github.com/x"), allowed)) == 1


def test_a_disabled_rule_flags_nothing():
    disabled = "version: 1\nrules:\n  unlisted_domain: {enabled: false}\n"
    assert r4(call("WebFetch", "https://example.com"), disabled) == []
