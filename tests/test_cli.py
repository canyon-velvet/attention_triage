import json
import os
import subprocess
from pathlib import Path

import pytest
from test_hook import FIXTURES, rows

from attention_triage import cli

EVENTS = cli.TOOL_EVENTS + cli.OTHER_EVENTS
USER_SETTINGS = {
    "model": "opus",
    "hooks": {
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "~/lint.sh"}]}]
    },
    "permissions": {"allow": ["Bash(ls:*)"]},
}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    """Every test gets its own HOME, so the real ~/.claude/settings.json is never touched."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def settings(home) -> Path:
    path = home / ".claude" / "settings.json"
    path.parent.mkdir()
    path.write_text(json.dumps(USER_SETTINGS, indent=2) + "\n")
    return path


def answer(monkeypatch, reply: str) -> None:
    monkeypatch.setattr("builtins.input", lambda prompt: reply)


def backups(settings: Path) -> list[Path]:
    return list(settings.parent.glob("settings.json.triage-backup-*"))


def test_dry_run_shows_the_diff_and_writes_nothing(settings, home, capsys):
    before = settings.read_bytes()
    cli.main(["install", "--dry-run"])
    added = [line for line in capsys.readouterr().out.splitlines() if line.startswith("+")]
    assert any("triage-hook" in line for line in added)
    assert settings.read_bytes() == before
    assert backups(settings) == [] and not (home / ".attention-triage").exists()


@pytest.mark.parametrize("reply", ["n", EOFError], ids=["no", "no-stdin"])
def test_declining_writes_nothing(settings, monkeypatch, capsys, reply):
    def decline(prompt):
        if reply is EOFError:
            raise EOFError
        return reply

    before = settings.read_bytes()
    monkeypatch.setattr("builtins.input", decline)
    cli.main(["install"])
    assert settings.read_bytes() == before and backups(settings) == []
    assert "Nothing written." in capsys.readouterr().out


def test_a_change_made_while_confirming_is_not_overwritten(settings, monkeypatch):
    def edit_then_confirm(prompt):
        settings.write_text(json.dumps({**USER_SETTINGS, "enabledPlugins": {"x": True}}))
        return "y"

    monkeypatch.setattr("builtins.input", edit_then_confirm)
    with pytest.raises(SystemExit, match="changed while waiting"):
        cli.main(["install"])
    assert "enabledPlugins" in json.loads(settings.read_text()) and backups(settings) == []


def test_install_backs_up_then_adds_one_async_entry_per_event(settings, home, monkeypatch, capsys):
    before = settings.read_bytes()
    answer(monkeypatch, "y")
    cli.main(["install"])
    assert '+  "model"' not in capsys.readouterr().out  # the diff shows only what changed
    [backup] = backups(settings)
    assert backup.read_bytes() == before
    installed = json.loads(settings.read_text())
    for event in EVENTS:
        [handler] = [
            h for group in installed["hooks"][event] for h in group["hooks"] if cli.is_ours(h)
        ]
        assert handler["async"] is True
    assert installed["hooks"]["PreToolUse"][0] == USER_SETTINGS["hooks"]["PreToolUse"][0]
    assert installed["model"] == "opus" and installed["permissions"] == USER_SETTINGS["permissions"]
    assert (home / ".attention-triage").is_dir()


def test_installing_twice_changes_nothing(settings, monkeypatch, capsys):
    answer(monkeypatch, "y")
    cli.main(["install"])
    once = settings.read_bytes()
    cli.main(["install"])
    assert settings.read_bytes() == once and len(backups(settings)) == 1
    assert "already installed" in capsys.readouterr().out


def test_the_installed_command_stores_an_event(home, monkeypatch):
    answer(monkeypatch, "y")
    cli.main(["install"])  # no settings.json yet: install creates it
    installed = json.loads((home / ".claude" / "settings.json").read_text())
    [group] = installed["hooks"]["PreToolUse"]
    stdin = (FIXTURES / "auto-write-in-project" / "01-PreToolUse.json").read_bytes()
    env = {**os.environ, "HOME": str(home)}
    subprocess.run(group["hooks"][0]["command"], shell=True, input=stdin, env=env, check=True)
    assert len(rows(home)) == 1
