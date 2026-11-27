---
description: Show the most recent tool calls Agent Guard flagged, blocked or asked about
argument-hint: "[count]"
allowed-tools: Bash(python3:*)
---

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/agentguard_lite.py" tail $ARGUMENTS`

Show these events to the user as a short list, newest last, and point out any pattern (for example repeated blocks on the same tool).
