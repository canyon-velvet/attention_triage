# Recorded hook payloads

Real Claude Code (2.1.293) hook payloads from the spike (#1), one folder per scenario. Files are numbered in **arrival order** at the hook, which is not always the order the events happened in. Findings are recorded in SPEC.md §10, "Spike findings".

Recorded with async hooks on all ten Triage events, sandbox enabled. The home dir is anonymised to `/Users/alice`, and two real directory listings are replaced with `<redacted: directory listing>`.

| folder | what happened |
|---|---|
| `session-lifecycle` | SessionStart, Stop, the internal SubagentStop that follows every Stop (empty `agent_type`, no SubagentStart), SessionEnd |
| `auto-sandbox-block-filesystem` | `touch ~/…` in the sandbox → PostToolUseFailure, "Operation not permitted" |
| `auto-bypass-retry-after-block` | the same command retried with `dangerouslyDisableSandbox: true` → ran, no prompt (auto mode) |
| `auto-sandbox-block-network` | `curl https://example.com` → PostToolUseFailure, proxy 403 + `<sandbox_violations>` |
| `auto-bypass-preemptive` | `ls ~/Desktop` with `dangerouslyDisableSandbox: true` on the first attempt |
| `auto-write-in-project` | Write inside the project |
| `auto-bash-write-in-project` | `echo … >> notes.txt` via Bash |
| `auto-write-outside-project` | Write to a sibling dir of the project |
| `auto-webfetch` | WebFetch of `https://example.com` |
| `auto-subagent` | Agent tool launching Explore, its SubagentStart, its own Bash calls (`agent_id` set), SubagentHandback, SubagentStop |
| `auto-curl-pipe-bash-allowed` | `curl … \| bash` allowed by auto mode (should-flag case for R4) |
| `default-prompt-approved-then-sandbox-block` | default mode: prompt approved, command then blocked by the sandbox |
| `default-prompt-approved-bypass-retry` | default mode: retry with the sandbox disabled, prompt approved; PermissionRequest arrived before PreToolUse |
| `default-prompt-approved-write` | default mode: Write prompt approved |
| `default-prompt-denied-by-user` | default mode: Edit prompt denied by the user; no later hook event exists |

Not recorded: a `PermissionDenied` (auto-mode classifier denial). Claude declined the test request itself, so the classifier never ran.
