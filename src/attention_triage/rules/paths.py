"""Where a file tool writes, for the rules that check file paths (R1, R3).

Paths are resolved when the event is captured, on this machine, so a symlink or `..` is followed to
the file it really writes.
"""

import os
from pathlib import Path

TOOLS = {"Write", "Edit", "NotebookEdit"}


def written_path(event: dict) -> Path | None:
    """The real absolute path a file tool call writes to; None for any other event."""
    if (
        event["event_type"] != "tool_call"
        or event["tool_name"] not in TOOLS
        or not event["target"]
        or not event["cwd"]
    ):
        return None
    # realpath follows symlinks and collapses `..`, also for a file (or dirs) not created yet.
    target = os.path.join(event["cwd"], os.path.expanduser(event["target"]))
    try:
        return Path(os.path.realpath(target))
    except ValueError:  # a NUL in the path: no file can be written there
        return None
