import hashlib
import json
from pathlib import Path

import pytest
from test_hook import rows, run_hook

from attention_triage.normalize import normalize
from attention_triage.redact import MASK, redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))

# Built by concatenation so GitHub push protection doesn't mistake them for leaked tokens.
PEM_BODY = "MIIEowIBAAKCAQEA" + "q" * 64
SECRETS = {
    "aws": ("aws configure set aws_access_key_id {}", "AKIA" + "IOSFODNN7EXAMPLE"),
    "github": ("git clone https://{}@github.com/me/repo", "ghp_" + "a1B2c3D4e5" * 4),
    "sk": ("curl -d @req.json -H 'x-model: claude' {} api", "sk-ant-api03-" + "Zx9" * 10),
    "bearer": (
        "curl -H 'Authorization: Bearer {}' https://api.example.com",
        "eyJhbGci.e30.sig_" + "Q" * 20,
    ),
    "pem": (
        "echo '{}' > id.pem",
        f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----",
    ),
    "pem-cut-off": ("echo '{}", f"-----BEGIN OPENSSH PRIVATE KEY-----\n{PEM_BODY}"),
    "key=value": ("DB_PASSWORD={} ./migrate", "hunter2-correct-horse"),
    "key: value": ('printf \'"api_key": "{}"\' > cfg.json', "abc123def456"),
}


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.parametrize("command, secret", SECRETS.values(), ids=SECRETS)
def test_secrets_are_masked_in_stored_rows(tmp_path, command, secret):
    payload = load("auto-sandbox-block-network/02-PostToolUseFailure.json")
    payload["tool_input"]["command"] = command.format(secret)
    payload["error"] = f"Exit code 1\n{command.format(secret)}: failed"
    run_hook(tmp_path, json.dumps(payload).encode())
    [row] = rows(tmp_path)
    for column in ("target", "summary", "raw"):
        assert secret not in row[column] and PEM_BODY not in row[column], column
        assert MASK in row[column], column


def test_values_under_secret_named_keys_are_masked():
    payload = {"tool_input": {"api_token": "plain-value", "max_tokens": "4096"}}
    assert redact(payload)["tool_input"] == {"api_token": MASK, "max_tokens": "4096"}


@pytest.mark.parametrize("path", ALL_FIXTURES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_ordinary_commands_paths_and_urls_are_left_alone(path):
    payload = json.loads(path.read_text())
    assert normalize(redact(payload))["target"] == normalize(payload)["target"]


def test_large_write_stores_hash_size_and_preview_not_contents(tmp_path):
    content = "API_KEY=abc123xyz\n" + "a line of the new file\n" * 5_000
    payload = load("auto-write-in-project/02-PostToolUse.json")
    payload["tool_input"]["content"] = payload["tool_response"]["content"] = content
    run_hook(tmp_path, json.dumps(payload).encode())
    [row] = rows(tmp_path)
    stored = json.loads(row["raw"])
    expected = {
        "sha256": hashlib.sha256(content.encode()).hexdigest(),
        "bytes": len(content.encode()),
        "preview": (f"API_KEY={MASK}\n" + "a line of the new file\n" * 25)[:500],
    }
    assert stored["tool_input"]["content"] == stored["tool_response"]["content"] == expected
    assert len(row["raw"]) < 5_000


def test_long_tool_output_keeps_its_head_and_tail(tmp_path):
    payload = load("auto-bash-write-in-project/02-PostToolUse.json")
    payload["tool_response"]["stdout"] = "start\n" + "x" * 10_000 + "\n<sandbox_violations>"
    run_hook(tmp_path, json.dumps(payload).encode())
    [row] = rows(tmp_path)
    stdout = json.loads(row["raw"])["tool_response"]["stdout"]
    assert len(stdout) < 2_050
    assert stdout.startswith("start\n") and stdout.endswith("\n<sandbox_violations>")


def test_limits_are_configurable():
    payload = load("auto-write-in-project/02-PostToolUse.json")
    payload["tool_response"]["stdout"] = "y" * 300
    redacted = redact(payload, preview_chars=3, max_chars=100)
    assert redacted["tool_input"]["content"]["preview"] == "hel"
    assert 100 <= len(redacted["tool_response"]["stdout"]) < 150
