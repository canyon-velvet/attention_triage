"""Claude Code hook payload -> agent-neutral event."""
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

AGENT = "claude-code"
INSTALL_SCOPE = "user"

EVENT_TYPES = {
    "PreToolUse": "tool_call",
    "PostToolUse": "tool_result",
    "PostToolUseFailure": "tool_failure",
    "PermissionRequest": "permission_request",
    "PermissionDenied": "permission_denied",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "Stop": "turn_end",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
}

# tool_input key -> target_kind; the first key present wins.
TARGET_KEYS = [("command", "command"), ("file_path", "path"), ("notebook_path", "path"), ("url", "url")]

# Small top-level payload fields worth keeping in the summary.
SUMMARY_KEYS = ["permission_mode", "agent_type", "source", "reason", "error", "is_interrupt"]


def normalize(payload: dict, now: datetime | None = None) -> dict:
    """Map one hook payload to the neutral event shape. Unknown event names pass through."""
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    target_kind, target = next(((kind, tool_input[key]) for key, kind in TARGET_KEYS if key in tool_input), (None, None))
    hook_event = payload.get("hook_event_name")
    event_type = EVENT_TYPES.get(hook_event, hook_event)
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    cwd = payload.get("cwd")
    return {
        "agent": AGENT,
        "session_id": payload.get("session_id"),
        "agent_id": payload.get("agent_id"),
        "event_type": event_type,
        "tool_name": payload.get("tool_name"),
        "tool_use_id": payload.get("tool_use_id"),
        "target_kind": target_kind,
        "target": target,
        "stated_reason": tool_input.get("description"),
        "project_root": project_root(cwd),
        "cwd": cwd,
        "ts": (now or datetime.now(UTC)).isoformat(timespec="milliseconds"),
        "summary": {key: payload[key] for key in SUMMARY_KEYS if key in payload},
        "raw": raw,
        "dedup_key": dedup_key(payload.get("session_id"), event_type, payload.get("tool_use_id"), raw),
        "install_scope": INSTALL_SCOPE,
    }


def dedup_key(session_id, event_type, tool_use_id, raw: str) -> str:
    """Same tool call and event -> same key. Events without a tool_use_id fall back to the full payload."""
    parts = [AGENT, session_id, event_type, tool_use_id or raw]
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()


def project_root(cwd: str | None) -> str | None:
    """Git root of cwd (nearest ancestor containing .git), else cwd itself."""
    if not cwd:
        return cwd
    path = Path(cwd)
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return str(candidate)
    return cwd
