---
description: Summarise what Agent Guard has blocked, asked about and flagged, by OWASP Agentic Top 10 category
allowed-tools: Bash(python3:*)
---

Agent Guard audit report:

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/agentguard_lite.py" report --format md`

Summarise this report for the user in a few sentences: how many actions were blocked or sent for approval, which risk categories and rules fired most, and anything critical worth a closer look. If there is no log yet, say so in one line.
