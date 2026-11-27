"""GitHub Copilot integration (Copilot CLI and the Copilot cloud coding agent).

Both read hook files with `{"version": 1, "hooks": {...}}`; the cloud agent
reads only `.github/hooks/*.json` from the repository, the CLI also reads
`~/.copilot/hooks/*.json`. We register camelCase events, whose payloads carry
`toolName`/`toolArgs` (`bash`, `view`, `create`, `edit`, MCP tools...). The
PascalCase, VS Code-compatible payload (`tool_name`/`tool_input`) is accepted
too, so the same command works if someone wires it up that way.

Copilot honours `permissionDecision: "ask"` in the CLI; the cloud agent treats
it as deny because nobody is there to answer. Command preToolUse hooks are
fail-closed on a non-zero exit, so this adapter always exits 0.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Decision, Verdict
from .hooks_base import (POST, PRE, PROMPT, SKIP, HookAdapter, HookEvent, HookReply, blocks,
                         injection_warning, make_call, read_json, reason, write_json)

HOOK_COMMAND = "agentguard hook copilot"
_PRE = {"preToolUse", "PreToolUse"}
_POST = {"postToolUse", "PostToolUse"}
_PROMPT = {"userPromptSubmitted", "UserPromptSubmit"}


class CopilotAdapter(HookAdapter):
    agent = "copilot"

    def parse(self, event: dict[str, Any]) -> HookEvent:
        # camelCase payloads carry no event name; tell them apart by their fields.
        name = str(event.get("hook_event_name") or event.get("hookEventName") or "")
        if not name:
            if "toolResult" in event:
                name = "postToolUse"
            elif "toolName" in event:
                name = "preToolUse"
            elif "prompt" in event:
                name = "userPromptSubmitted"
        session = event.get("sessionId", event.get("session_id"))
        cwd = event.get("cwd")
        if name in _PROMPT:
            return HookEvent(PROMPT, make_call(self.agent, "prompt", {}, session, cwd),
                             prompt=str(event.get("prompt", "")), raw=event, name=name)
        if name in _PRE or name in _POST:
            tool = str(event.get("toolName", event.get("tool_name", "unknown")))
            args = event.get("toolArgs", event.get("tool_input"))
            res = event.get("toolResult", event.get("tool_result")) or {}
            text = res.get("textResultForLlm", res.get("text_result_for_llm", res)) if isinstance(res, dict) else res
            kind = PRE if name in _PRE else POST
            return HookEvent(kind, make_call(self.agent, tool, args, session, cwd), result=text, raw=event, name=name)
        return HookEvent(SKIP, raw=event, name=name)

    def reply_pre(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not blocks(verdict):
            return HookReply()
        return HookReply({"permissionDecision": "deny" if verdict.decision == Decision.BLOCK else "ask",
                          "permissionDecisionReason": reason(verdict)})

    def reply_post(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not verdict.findings:
            return HookReply()
        return HookReply({"additionalContext": injection_warning(verdict)})

    def settings_path(self, user: bool, cwd: Path) -> Path:
        import os
        if user:
            return Path(os.environ.get("COPILOT_HOME", Path.home() / ".copilot")) / "hooks" / "agentguard.json"
        return cwd / ".github" / "hooks" / "agentguard.json"

    def install(self, path: Path) -> Path:
        data = read_json(path)
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        for event in ("userPromptSubmitted", "preToolUse", "postToolUse"):
            entries = hooks.setdefault(event, [])
            if not any(e.get("bash") == HOOK_COMMAND for e in entries):
                entries.append({"type": "command", "bash": HOOK_COMMAND, "powershell": HOOK_COMMAND, "timeoutSec": 30})
        return write_json(path, data)
