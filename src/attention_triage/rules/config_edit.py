"""R3 `config_edit`: a file tool edited what controls the agent or Triage: Claude Code's settings and
hooks, or Triage's own policy and data (SPEC.md §5).

Writes made by Bash commands are not seen (v1 gap).
"""

import os
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
    found.append((str(store.data_dir()), "Triage's data"))
    found += [
        (os.path.expanduser(p), "extra_protected_paths") for p in settings["extra_protected_paths"]
    ]
    return found


def fold(path: str) -> str:
    """macOS volumes ignore case by default, so `.claude/Settings.json` is settings.json; realpath
    keeps the case as written. (This may over-flag on a rare case-sensitive volume.)"""
    return path.lower() if sys.platform == "darwin" else path
