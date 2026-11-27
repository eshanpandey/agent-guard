"""OpenAI Codex CLI integration via its hooks (hooks.json).

Codex hooks use the same nested layout and much the same payload as Claude
Code: `PreToolUse`, `PostToolUse` and `UserPromptSubmit` events with
`tool_name`/`tool_input` on stdin. Tool names are `Bash` (shell and unified
exec), `apply_patch` (file edits; the patch text is in `tool_input.command`)
and `mcp__<server>__<tool>`.

Two Codex-specific points:
* Codex does not support `permissionDecision: "ask"` in PreToolUse (it reports
  the hook as failed and runs the tool). So calls our policy would *ask*
  about are denied here, with a reason telling the agent to get the user's
  go-ahead. Use `mode: monitor` in the policy if you prefer flag-only.
* Codex only runs hooks the user has reviewed and trusted (`/hooks` in the
  CLI). `agentguard install codex` writes the file; trusting it is up to you.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Decision, Verdict
from .hooks_base import (POST, PRE, PROMPT, SKIP, HookAdapter, HookEvent, HookReply, add_nested_hook,
                         blocks, injection_warning, make_call, read_json, reason, write_json)

HOOK_COMMAND = "agentguard hook codex"


class CodexAdapter(HookAdapter):
    agent = "codex"
    post_install_note = ("Codex runs only hooks you have trusted: start Codex, run /hooks and approve "
                         "the three Agent Guard hooks.")

    def parse(self, event: dict[str, Any]) -> HookEvent:
        name = str(event.get("hook_event_name", ""))
        session, cwd = event.get("session_id"), event.get("cwd")
        if name == "UserPromptSubmit":
            return HookEvent(PROMPT, make_call(self.agent, "prompt", {}, session, cwd),
                             prompt=str(event.get("prompt", "")), raw=event, name=name)
        if name in ("PreToolUse", "PostToolUse"):
            call = make_call(self.agent, str(event.get("tool_name", "unknown")), event.get("tool_input"), session, cwd)
            kind = PRE if name == "PreToolUse" else POST
            return HookEvent(kind, call, result=event.get("tool_response"), raw=event, name=name)
        return HookEvent(SKIP, raw=event, name=name)

    def reply_pre(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not blocks(verdict):
            return HookReply()
        why = reason(verdict)
        if verdict.decision == Decision.ASK:
            why += (" (needs the user's confirmation; Codex hooks cannot ask, so the call was stopped. "
                    "Tell the user what you wanted to do and why, and let them run it or approve it.)")
        return HookReply({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "permissionDecision": "deny",
                                                 "permissionDecisionReason": why}})

    def reply_post(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not verdict.findings:
            return HookReply()
        return HookReply({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                 "additionalContext": injection_warning(verdict)}})

    def settings_path(self, user: bool, cwd: Path) -> Path:
        import os
        if user:
            return Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "hooks.json"
        return cwd / ".codex" / "hooks.json"

    def install(self, path: Path) -> Path:
        data = read_json(path)
        hooks = data.setdefault("hooks", {})
        for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse"):
            add_nested_hook(hooks, event, HOOK_COMMAND, None, {"timeout": 30, "statusMessage": "Agent Guard"})
        return write_json(path, data)
