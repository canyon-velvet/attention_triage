"""R1 `outside_project_write`: a file tool wrote outside the project and the dirs agents may use.

A symlink or `..` that leads out of the project is caught (rules/paths.py). Writes made by Bash
commands are not seen (v1 gap, SPEC.md §5).
"""

import os
from pathlib import Path

from attention_triage.rules.paths import written_path

TEMP_DIRS = ["/tmp", "/private/tmp", "/var/folders"]


def check(event: dict, settings: dict) -> dict | None:
    if not (path := written_path(event)):
        return None
    if is_memory(path) or any(path.is_relative_to(root) for root in allowed_roots(event, settings)):
        return None
    return {
        "reason": "The agent asked to write a file outside the project.",
        "label": "",
        "evidence": {"path": str(path), "project_root": event["project_root"]},
    }


def allowed_roots(event: dict, settings: dict) -> list[str]:
    roots = [
        event["project_root"],
        *TEMP_DIRS,
        os.environ.get("TMPDIR"),  # the hook inherits Claude Code's environment
        "~/.claude/plans",
        "~/.claude/jobs",
        *settings["allowed_paths"],
    ]
    return [os.path.realpath(os.path.expanduser(root)) for root in roots if root]


def is_memory(path: Path) -> bool:
    """Claude Code's auto-memory, ~/.claude/projects/<project>/memory/, of any project."""
    projects = Path(os.path.realpath(os.path.expanduser("~/.claude/projects")))
    return path.is_relative_to(projects) and path.relative_to(projects).parts[1:2] == ("memory",)
