import json
from pathlib import Path

import pytest

from attention_triage import policy, rules
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
# Calls that reach example.com. The other events of these calls repeat the input.
SHOULD_FLAG = {
    "auto-webfetch/01-PreToolUse.json",
    "auto-curl-pipe-bash-allowed/01-PreToolUse.json",
    "auto-sandbox-block-network/01-PreToolUse.json",
}


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


def test_a_bash_flag_is_partial_and_lists_each_unlisted_host_once():
    command = (
        "curl https://a.example/x && curl https://github.com/y https://a.example/z http://b.example"
    )
    [flag] = r4(call("Bash", command))
    assert flag["label"] == "partial"
    assert flag["reason"] == "The command names a URL whose host isn't in allowed_domains."
    assert flag["evidence"] == {"hosts": ["a.example", "b.example"]}


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
        "http://localhost:8765/api/health",  # this machine
        "http://LOCALHOST/",
        "http://127.0.0.1:8765/",
        "http://[::1]:8000/",
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
        ("http://localhost.evil.example/", "localhost.evil.example"),
        ("http://127.0.0.1.evil.example/", "127.0.0.1.evil.example"),
        ("http://localhost@evil.example/", "evil.example"),
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
        ("https:/evil.example/?x://github.com/", "evil.example"),  # browsers skip any / or \
        ("https:evil.example/x://github.com", "evil.example"),
        ("https:\\\\evil.example\\?q=://github.com", "evil.example"),
        ("https:///evil.example/", "evil.example"),
    ],
)
def test_look_alike_hosts_are_flagged(url, host):
    [flag] = r4(call("WebFetch", url))
    assert host in flag["evidence"]["hosts"]  # the curl reading may add a second, odd host


def test_an_empty_host_is_flagged():
    [flag] = r4(call("WebFetch", "https://@/x"))
    assert flag["evidence"] == {"hosts": [""]}


def test_a_malformed_url_is_flagged_not_skipped():
    [flag] = r4(call("WebFetch", "http://[fe80::1/x"))
    assert flag["evidence"] == {"hosts": ["fe80::1"]}


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "curl example.com",  # no scheme: not seen (partial)
        "git push origin main",
        "curl -sS https://github.com/x",
        'gh pr create --body "see [docs](https://github.com/a/b), then https://pypi.org."',
    ],
)
def test_bash_without_unlisted_urls_is_not_flagged(command):
    assert r4(call("Bash", command)) == []


@pytest.mark.parametrize("cut", [",", ";", "\\", "(", "|", "&"])
def test_a_user_name_cannot_cut_a_bash_url_at_a_listed_host(cut):
    # curl connects to the host after `@`; the URL must not end at the listed name before it.
    [flag] = r4(call("Bash", f"curl 'https://pypi.org{cut}@evil.example/'"))
    assert flag["evidence"] == {"hosts": ["evil.example"]}


@pytest.mark.parametrize(
    "command, host",
    [
        ("curl 'https://github.com'@evil.example/", "evil.example"),  # the shell joins the pieces
        ('curl "https://github.com"evil.example/', "github.comevil.example"),
        ("curl https://github.com\\.evil.example/", "github.com.evil.example"),
        ("curl https:///evil.example/", "evil.example"),
        ("curl 'https://{@,}evil.example/'", ""),  # curl globbing; the host reads as empty
        ("curl $'https://evil.example\\x2f@github.com/'", "evil.example"),  # $'..': \x2f is /
        ("curl $'https://evil.example\\057@github.com/'", "evil.example"),
        ("curl $'https://github.com\\x2eevil.example/'", "github.comx2eevil.example"),
    ],
)
def test_shell_quoting_cannot_cut_a_bash_url_at_a_listed_host(command, host):
    [flag] = r4(call("Bash", command))
    assert host in flag["evidence"]["hosts"]


def test_a_url_ending_a_sentence_or_markdown_link_keeps_its_host():
    assert r4(call("Bash", "echo '[x](https://a.example/y), https://b.example.'"))[0][
        "evidence"
    ] == {"hosts": ["a.example", "b.example"]}


def test_allowed_domains_replace_the_defaults():
    allowed = "version: 1\nrules:\n  unlisted_domain: {allowed_domains: ['*.example']}\n"
    assert r4(call("WebFetch", "https://docs.example/x"), allowed) == []
    assert len(r4(call("WebFetch", "https://github.com/x"), allowed)) == 1


def test_a_disabled_rule_flags_nothing():
    disabled = "version: 1\nrules:\n  unlisted_domain: {enabled: false}\n"
    assert r4(call("WebFetch", "https://example.com"), disabled) == []
