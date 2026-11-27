#!/usr/bin/env python3
"""Claude Code hook entry point for the Agent Guard plugin.

Runs on the standard library alone: it loads the agentguard package bundled
with the plugin (src/), so `/plugin install` needs no pip step. PyYAML, if
present, is used for policy files; without it a simple YAML subset is read.
Fails open: if Agent Guard itself breaks, the tool call goes ahead.
"""

import os
import sys

ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

if sys.version_info < (3, 10):
    sys.stderr.write("agentguard: Python 3.10+ is required; allowing call\n")
    sys.exit(0)

try:
    from agentguard.integrations.claude_code import run_hook
except Exception as exc:  # fail open
    sys.stderr.write(f"agentguard: could not load ({exc}); allowing call\n")
    sys.exit(0)

sys.exit(run_hook())
