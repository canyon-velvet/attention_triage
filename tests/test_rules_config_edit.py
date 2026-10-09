import json
from pathlib import Path

import pytest

from attention_triage import policy, rules
from attention_triage.normalize import normalize
from attention_triage.redact import redact

FIXTURES = Path(__file__).parent / "fixtures" / "payloads"
ALL_FIXTURES = sorted(FIXTURES.glob("*/*.json"))


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture
def project(tmp_path):
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    return project


def write(path, cwd, tool: str = "Write") -> dict:
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s1",
        "tool_use_id": "t1",
        "cwd": str(cwd),
        "tool_name": tool,
        "tool_input": {"file_path": str(path)},
    }
    return normalize(payload)


def r3(event: dict, policy_text: str = policy.DEFAULT_POLICY) -> list[dict]:
    flags = rules.evaluate(event, *policy.parse(policy_text))
    return [f for f in flags if f["rule_id"] == "config_edit"]


def fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


@pytest.mark.parametrize("name", [fixture_id(path) for path in ALL_FIXTURES])
def test_no_recorded_fixture_edits_config(name):
    assert r3(normalize(redact(json.loads((FIXTURES / name).read_text())))) == []


@pytest.mark.parametrize(
    "path",
    [
        "{home}/.claude/settings.json",
        "{home}/.claude/settings.local.json",
        "{home}/.claude/hooks/guard.sh",
        "{home}/.claude/hooks/sub/check.py",
        "{project}/.claude/settings.json",
        "{project}/.claude/settings.local.json",
        "{project}/.claude/hooks/guard.sh",
        "{project}/sub/../.claude/settings.json",
        "{home}/.attention-triage/policy.yaml",
        "{home}/.attention-triage/triage.db",
    ],
)
def test_edits_to_settings_hooks_and_triage_data_are_flagged(path, home, project):
    assert len(r3(write(path.format(home=home, project=project), project))) == 1


@pytest.mark.parametrize(
    "path",
    [
        "{project}/src/x.py",
        "{project}/settings.json",
        "{project}/.claude/agents/reviewer.md",
        "{home}/.claude/settings.json.bak",
        "{home}/.claude/hooks-old/guard.sh",
        "{home}/.attention-triage-old/policy.yaml",
    ],
)
def test_other_writes_are_not_flagged(path, home, project):
    assert r3(write(path.format(home=home, project=project), project)) == []


def test_the_flag_names_the_path_and_why_it_is_protected(home, project):
    [flag] = r3(write("~/.claude/settings.json", project, tool="Edit"))
    assert flag["severity"] == "high"
    assert (
        flag["reason"]
        == "The agent asked to edit Claude Code's settings or hooks, or Triage's data."
    )
    assert flag["label"] == ""
    assert flag["evidence"] == {
        "path": str(home / ".claude" / "settings.json"),
        "protected": "Claude Code settings",
    }


@pytest.mark.parametrize("platform, flagged", [("darwin", 1), ("linux", 0)])
def test_letter_case_is_ignored_on_macos(project, monkeypatch, platform, flagged):
    monkeypatch.setattr("sys.platform", platform)
    assert len(r3(write(project / ".claude" / "Settings.Local.json", project))) == flagged


def test_a_symlink_into_the_claude_dir_is_flagged(home, project):
    (project / "link").symlink_to(home / ".claude")
    assert len(r3(write(project / "link" / "settings.json", project))) == 1


def test_scripts_run_by_hooks_are_flagged(home, project):
    hooks = {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "~/bin/guard.sh --strict"}],
            }
        ],
        "Stop": [
            {
                "hooks": [
                    {"type": "command", "command": "python3 $CLAUDE_PROJECT_DIR/scripts/stop.py"}
                ]
            }
        ],
    }
    settings = home / ".claude" / "settings.json"
    settings.write_text(json.dumps({"hooks": hooks}))
    [flag] = r3(write(home / "bin" / "guard.sh", project))
    assert flag["evidence"]["protected"] == f"hook script run by {settings}"
    assert len(r3(write(project / "scripts" / "stop.py", project))) == 1
    assert r3(write(home / "bin" / "other.sh", project)) == []


def test_project_settings_hook_scripts_are_flagged(project):
    hook = {"hooks": [{"type": "command", "command": '"./tools/my hook.sh"'}]}
    settings = {"hooks": {"Stop": [hook]}}
    (project / ".claude" / "settings.local.json").write_text(json.dumps(settings))
    assert len(r3(write(project / "tools" / "my hook.sh", project))) == 1


def test_env_vars_in_hook_commands_are_expanded(home, project):
    hook = {"hooks": [{"type": "command", "command": "${HOME}/bin/guard.sh"}]}
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"Stop": [hook]}}))
    assert len(r3(write(home / "bin" / "guard.sh", project))) == 1


@pytest.mark.parametrize(
    "command", ['cd "$CLAUDE_PROJECT_DIR" && npm run lint', "jq -r .file_path | tr / _", "ls ~/"]
)
def test_dirs_named_in_hook_commands_are_not_protected(home, project, command):
    hook = {"hooks": [{"type": "command", "command": command}]}
    (home / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"Stop": [hook]}}))
    assert r3(write(project / "src" / "x.py", project)) == []
    assert r3(write(home / "notes.txt", project)) == []


@pytest.mark.parametrize(
    "text", ["{not json", '{"hooks": []}', '{"hooks": {"Stop": [{"hooks": [1]}]}}', "[]"]
)
def test_unreadable_settings_still_protect_themselves(home, project, text):
    (home / ".claude" / "settings.json").write_text(text)
    assert len(r3(write(home / ".claude" / "settings.json", project))) == 1
    assert r3(write(project / "x.py", project)) == []


def test_extra_protected_paths_with_a_tilde_are_flagged(home, project):
    extra = "version: 1\nrules:\n  config_edit: {extra_protected_paths: ['~/.zshrc']}\n"
    [flag] = r3(write(home / ".zshrc", project), extra)
    assert flag["evidence"]["protected"] == "extra_protected_paths"
    assert r3(write(home / ".zshrc.bak", project), extra) == []


def test_a_disabled_rule_flags_nothing(project):
    disabled = "version: 1\nrules:\n  config_edit: {enabled: false}\n"
    assert r3(write("~/.claude/settings.json", project), disabled) == []
