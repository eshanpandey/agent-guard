---
description: Show Agent Guard's active mode, policy and where its audit log lives
allowed-tools: Bash(python3:*)
---

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/agentguard_lite.py" status`

Relay this status to the user. If PyYAML is missing and they want custom rules, tell them to run `pip install pyyaml` for the Python 3 that Claude Code uses. Mention that `.agentguard.yaml` in the project folder changes the policy.
