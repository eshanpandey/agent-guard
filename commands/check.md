---
description: Ask Agent Guard what it would do with a tool call, without running it
argument-hint: "<tool> <shell command or JSON input>"
allowed-tools: Bash(python3:*)
---

The user wants to know how Agent Guard would judge this tool call: $ARGUMENTS

Run it through the checker, without executing the call itself. The first word is the tool name (for example Bash, Write, WebFetch); the rest is a shell command or the tool input as JSON. Use:

`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/agentguard_lite.py" check <tool> '<command or JSON>'`

Then explain the verdict (allow, flag, ask or block) and each finding in plain words.
