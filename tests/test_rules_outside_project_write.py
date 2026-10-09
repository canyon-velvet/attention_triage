import json
from pathlib import Path

import pytest

from attention_triage import policy, rules
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))
# Write to /Users/alice/Dev/triage-spike-outside, a sibling sharing the project's name as a prefix.
SHOULD_FLAG = {"auto-write-outside-project/01-PreToolUse.json"}
PROJECT = "/Users/alice/Dev/proj"


@pytest.fixture(autouse=True)
def home(monkeypatch):
    monkeypatch.setenv("HOME", "/Users/alice")  # the fixtures' anonymised home; it needn't exist
    monkeypatch.delenv("TMPDIR", raising=False)


def write(path: str, tool: str = "Write", cwd: str = PROJECT) -> dict:
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "tool_use_id": "t1",
        "cwd": cwd,
        "tool_name": tool,
        "tool_input": {key: path},
    }
    return normalize(payload)


def r1(event: dict, policy_text: str = policy.DEFAULT_POLICY) -> list[dict]:
    flags = rules.evaluate(event, *policy.parse(policy_text))
    return [f for f in flags if f["rule_id"] == "outside_project_write"]


def fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


@pytest.mark.parametrize("name", [fixture_id(path) for path in ALL_FIXTURES])
def test_only_file_tool_calls_outside_the_project_are_flagged(name):
    event = normalize(redact(json.loads((FIXTURES / name).read_text())))
    assert len(r1(event)) == (1 if name in SHOULD_FLAG else 0)


def test_the_flag_names_the_resolved_path_and_the_project_root():
    [flag] = r1(write("/Users/alice/Dev/other/./x.txt"))
    assert flag["severity"] == "high"
    assert flag["reason"] == "The agent asked to write a file outside the project."
    assert flag["label"] == ""
    assert flag["evidence"] == {"path": "/Users/alice/Dev/other/x.txt", "project_root": PROJECT}


@pytest.mark.parametrize("tool", ["Write", "Edit", "NotebookEdit"])
def test_each_file_tool_is_checked(tool):
    assert len(r1(write("/Users/alice/notes.ipynb", tool))) == 1


@pytest.mark.parametrize(
    "path",
    [
        f"{PROJECT}/../other/x.txt",  # `..` out of the project
        f"{PROJECT}/sub/../../proj-old/x.txt",
        "/Users/alice/Dev/proj-old/x.txt",  # a sibling sharing the project's name as a prefix
        "/Users/alice/.claude/settings.json",
        "/Users/alice/.claude/projects/-Users-alice-Dev-proj/s1.jsonl",  # a transcript, not memory
    ],
)
def test_writes_outside_the_project_are_flagged(path):
    assert len(r1(write(path))) == 1


@pytest.mark.parametrize(
    "path",
    [
        f"{PROJECT}/src/x.py",
        f"{PROJECT}/sub/../x.py",
        "/tmp/x.txt",
        "/private/tmp/claude-501/scratchpad/x.txt",
        "/var/folders/ab/xyz/T/x.txt",
        "/Users/alice/.claude/plans/plan.md",
        "/Users/alice/.claude/jobs/cf33f346/tmp/x.py",
        "/Users/alice/.claude/projects/-Users-alice-Dev-other/memory/notes.md",
    ],
)
def test_writes_to_the_project_temp_dirs_and_claude_code_session_dirs_are_allowed(path):
    assert r1(write(path)) == []


def test_tmpdir_is_allowed(monkeypatch):
    monkeypatch.setenv("TMPDIR", "/Users/alice/scratch")
    assert r1(write("/Users/alice/scratch/x.txt")) == []


def test_a_symlink_out_of_the_project_is_flagged(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "link").symlink_to("/Users/alice/elsewhere")
    [flag] = r1(write(str(project / "link" / "x.txt"), cwd=str(project)))
    assert flag["evidence"]["path"] == "/Users/alice/elsewhere/x.txt"


def test_a_relative_path_is_resolved_from_cwd():
    assert len(r1(write("../other/x.txt", cwd=f"{PROJECT}/src"))) == 1
    assert r1(write("x.txt", cwd=f"{PROJECT}/src")) == []


def test_allowed_paths_with_a_tilde_are_allowed():
    allowed = "version: 1\nrules:\n  outside_project_write: {allowed_paths: ['~/.cache/myapp']}\n"
    assert r1(write("/Users/alice/.cache/myapp/x.txt"), allowed) == []
    assert len(r1(write("/Users/alice/.cache/myapp-old/x.txt"), allowed)) == 1


def test_a_disabled_rule_flags_nothing():
    disabled = "version: 1\nrules:\n  outside_project_write: {enabled: false}\n"
    assert r1(write("/Users/alice/x.txt"), disabled) == []
