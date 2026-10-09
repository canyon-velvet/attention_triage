"""R3 `config_edit`: a file tool edited what controls the agent or Triage: Claude Code's settings and
hooks, the scripts those hooks run, or Triage's own policy and data (SPEC.md §5).

Writes made by Bash commands are not seen (v1 gap).
"""

import json
import os
import shlex
import sys
from pathlib import Path

from attention_triage import store
from attention_triage.rules.paths import written_path

SETTINGS_FILES = ["settings.json", "settings.local.json"]


def check(event: dict, settings: dict) -> dict | None:
    if not (path := written_path(event)):
        return None
    for protected, why in protected_paths(event["project_root"], settings):
        if Path(fold(str(path))).is_relative_to(fold(os.path.realpath(protected))):
            return {
                "reason": "The agent asked to edit Claude Code's settings or hooks, or Triage's data.",
                "label": "",
                "evidence": {"path": str(path), "protected": why},
            }
    return None


def protected_paths(project_root: str, settings: dict) -> list[tuple[str, str]]:
    """(path, why it is protected); a dir protects everything under it."""
    found = []
    for claude in [os.path.expanduser("~/.claude"), os.path.join(project_root, ".claude")]:
        found.append((os.path.join(claude, "hooks"), "Claude Code hooks"))
        for name in SETTINGS_FILES:
            file = os.path.join(claude, name)
            found.append((file, "Claude Code settings"))
            found += [(s, f"hook script run by {file}") for s in hook_scripts(file, project_root)]
    found.append((str(store.data_dir()), "Triage's data"))
    found += [
        (os.path.expanduser(p), "extra_protected_paths") for p in settings["extra_protected_paths"]
    ]
    return found


def fold(path: str) -> str:
    """macOS volumes ignore case by default, so `.claude/Settings.json` is settings.json; realpath
    keeps the case as written. (This may over-flag on a rare case-sensitive volume.)"""
    return path.lower() if sys.platform == "darwin" else path


def hook_scripts(settings_file: str, project_root: str) -> list[str]:
    """The paths in a settings file's hook commands: each word with a `/`, read now so a script
    added since the session started is covered. A file Claude Code couldn't use gives none."""
    try:
        with open(settings_file) as f:
            hooks = json.load(f).get("hooks") or {}
        commands = [
            hook["command"]
            for groups in hooks.values()
            for group in groups
            for hook in group["hooks"]
            if hook.get("type") == "command"
        ]
    except (OSError, ValueError, AttributeError, KeyError, TypeError):
        return []
    scripts = []
    for command in commands:
        command = str(command).replace("${CLAUDE_PROJECT_DIR}", project_root)
        command = command.replace("$CLAUDE_PROJECT_DIR", project_root)
        try:
            words = shlex.split(command)
        except ValueError:  # unbalanced quotes
            words = command.split()
        # A relative word is read from the project root. A NUL would make realpath raise.
        scripts += [
            os.path.join(project_root, os.path.expanduser(word))
            for word in words
            if "/" in word and "\0" not in word
        ]
    return scripts
