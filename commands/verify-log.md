---
description: Check that Agent Guard's audit log has not been edited, reordered or truncated
allowed-tools: Bash(python3:*)
---

!`python3 "${CLAUDE_PLUGIN_ROOT}/scripts/agentguard_lite.py" verify`

Tell the user in one or two sentences whether the hash chain is intact. If it reports TAMPERED, explain that a record was changed or removed after it was written, name the record number, and suggest keeping a copy of the file for investigation.
