"""Storage limits (SPEC.md §4): what reaches the DB is what ran and where, not contents or secrets.

redact() runs on the hook payload before normalize(), so every stored field (target, summary, raw,
...) is derived from the redacted copy.
"""

import hashlib
import json
import re

PREVIEW_CHARS = 500  # of file contents
MAX_CHARS = 2000  # of any other string; mostly tool output
MASK = "[REDACTED]"

# Keys holding file contents: Write/Edit/NotebookEdit inputs, their echoes in tool_response, Read
# output, and the diffs of files a Bash command changed (bashEditDiff hunks).
CONTENT_KEYS = {
    "content",
    "old_string",
    "new_string",
    "new_source",
    "oldString",
    "newString",
    "originalFile",
    "structuredPatch",
    "hunks",
}

# Starts at a word start; without the lookbehind a long word takes quadratic time to scan.
SECRET_NAME = r"(?<![\w-])[\w-]*(?:key|secret|token|password|passwd)"
SECRET_KEY = re.compile(rf"(?i){SECRET_NAME}$")
# (pattern, replacement); a replacement starting with \g<1> keeps the label in front of the secret.
SECRET_PATTERNS = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), MASK),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), MASK),
    (re.compile(r"\bsk-[\w-]{16,}"), MASK),
    # A block cut off before its END line is masked to the end of the string.
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:.*?-----END [A-Z ]*PRIVATE KEY-----|.*)",
            re.DOTALL,
        ),
        MASK,
    ),
    (re.compile(r"(?i)\b(bearer\s+)[\w.~+/=-]+"), rf"\g<1>{MASK}"),
    # api_key=..., "password": "...", --token=..., x-api-key: ..., and quotes escaped as \" (inside
    # a quoted command, or a JSON-dumped patch). A quoted value is masked whole, spaces included.
    (
        re.compile(
            rf"(?i)({SECRET_NAME}\\?[\"']?\s*[:=]\s*)(?:\\?\"[^\"]*\"|'[^']*'|[^\s\"'\\,;&]+)"
        ),
        rf"\g<1>{MASK}",
    ),
]


def redact(value, preview_chars: int = PREVIEW_CHARS, max_chars: int = MAX_CHARS, key=None):
    """Copy of a payload that is safe to store. Contents become a digest, secrets are masked and
    long strings are cut. `key` is the dict key `value` sits under."""
    if key in CONTENT_KEYS and value is not None:
        return digest(value, preview_chars)
    if key and SECRET_KEY.search(key) and value is not None:
        return MASK
    if isinstance(value, str):
        return cut(mask(value), max_chars)
    if isinstance(value, dict):
        return {k: redact(v, preview_chars, max_chars, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, preview_chars, max_chars) for v in value]
    return value


def digest(value, preview_chars: int) -> dict:
    """File contents -> sha256 and byte size of the full text, plus its masked start."""
    content = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    data = content.encode()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "preview": mask(content)[:preview_chars],
    }


def mask(text: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def cut(text: str, max_chars: int) -> str:
    """Keep the head and the tail: a sandbox denial's <sandbox_violations> block comes last."""
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return f"{text[:half]}…[{len(text) - 2 * half} chars cut]…{text[len(text) - half :]}"
