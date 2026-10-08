"""Add or remove the payload recorder's hooks in ~/.claude/settings.json.

    python3 settings_hooks.py install     # backs up settings, adds a top-level "hooks" key
    python3 settings_hooks.py uninstall   # removes it again

Install refuses if a "hooks" key already exists, so uninstall can simply delete it.
The hook runs record_hook.py with the same Python that ran install.
"""
import json
import shlex
import shutil
import sys
from pathlib import Path

SETTINGS = Path.home() / ".claude" / "settings.json"
COMMAND = shlex.join([sys.executable, str(Path(__file__).resolve().parent / "record_hook.py")])
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied"]
OTHER_EVENTS = ["SessionStart", "SessionEnd", "Stop", "SubagentStart", "SubagentStop"]


def hooks():
    handler = {"type": "command", "command": COMMAND, "async": True}
    result = {e: [{"matcher": "*", "hooks": [handler]}] for e in TOOL_EVENTS}
    result.update({e: [{"hooks": [handler]}] for e in OTHER_EVENTS})
    return result


def main(action):
    settings = json.loads(SETTINGS.read_text())
    if action == "install":
        if "hooks" in settings:
            sys.exit("settings.json already has a \"hooks\" key; merge by hand instead.")
        shutil.copy(SETTINGS, SETTINGS.with_name("settings.json.bak-triage-spike"))
        settings["hooks"] = hooks()
    elif action == "uninstall":
        settings.pop("hooks", None)
    else:
        sys.exit(__doc__)
    SETTINGS.write_text(json.dumps(settings, indent=2) + "\n")
    print(f"{action}ed. Restart Claude Code for it to take effect.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
