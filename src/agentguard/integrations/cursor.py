"""Cursor integration via hooks.json (Cursor editor agent and Cursor CLI).

We register four events:
* `beforeShellExecution` for terminal commands. It is the only Cursor event
  documented to honour `permission: "ask"`, so shell calls get the full
  allow / ask / deny range.
* `preToolUse` for every other tool (`Read`, `Write`, `Delete`, `MCP:<tool>`...).
  It also fires for `Shell`, which we skip there so a command is not counted
  twice. preToolUse documents only allow/deny, so "ask" becomes deny.
* `postToolUse` to scan tool output for planted instructions.
* `beforeSubmitPrompt` to record what the user asked for.

Cursor blocks a permission hook whose stdout is not valid JSON, so this
adapter always prints a JSON object, including when it fails internally.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Decision, Verdict
from .hooks_base import (POST, PRE, PROMPT, SKIP, HookAdapter, HookEvent, HookReply, blocks,
                         injection_warning, make_call, read_json, reason, write_json)

HOOK_COMMAND = "agentguard hook cursor"
_EVENTS = ("beforeSubmitPrompt", "beforeShellExecution", "preToolUse", "postToolUse")


class CursorAdapter(HookAdapter):
    agent = "cursor"

    def parse(self, event: dict[str, Any]) -> HookEvent:
        name = str(event.get("hook_event_name", ""))
        session = event.get("conversation_id") or event.get("session_id")
        roots = event.get("workspace_roots") or []
        cwd = event.get("cwd") or (roots[0] if roots else None)
        if name == "beforeSubmitPrompt":
            return HookEvent(PROMPT, make_call(self.agent, "prompt", {}, session, cwd),
                             prompt=str(event.get("prompt", "")), raw=event, name=name)
        if name == "beforeShellExecution":
            call = make_call(self.agent, "Shell", {"command": event.get("command", "")}, session, cwd)
            return HookEvent(PRE, call, raw=event, name=name)
        if name in ("preToolUse", "postToolUse"):
            tool = str(event.get("tool_name", "unknown"))
            if name == "preToolUse" and tool == "Shell":
                return HookEvent(SKIP, raw=event, name=name)  # handled by beforeShellExecution
            if tool.startswith("MCP:"):
                tool = tool[4:]
            call = make_call(self.agent, tool, event.get("tool_input"), session, cwd)
            kind = PRE if name == "preToolUse" else POST
            return HookEvent(kind, call, result=event.get("tool_output"), raw=event, name=name)
        return HookEvent(SKIP, raw=event, name=name)

    def _permission(self, decision: str, ev: HookEvent, verdict: Verdict | None = None) -> HookReply:
        out: dict[str, Any] = {"permission": decision}
        if verdict is not None and decision != "allow":
            out["user_message"] = reason(verdict)
            out["agent_message"] = reason(verdict) + (
                " Explain to the user what you wanted to do and why." if verdict.decision == Decision.ASK else "")
        return HookReply(out)

    def reply_pre(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not blocks(verdict):
            return self._permission("allow", ev)
        if verdict.decision == Decision.BLOCK:
            return self._permission("deny", ev, verdict)
        return self._permission("ask" if ev.name == "beforeShellExecution" else "deny", ev, verdict)

    def reply_post(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not verdict.findings:
            return HookReply({})
        return HookReply({"additional_context": injection_warning(verdict)})

    def reply_prompt(self, ev: HookEvent) -> HookReply:
        return HookReply({"continue": True})

    def reply_skip(self, ev: HookEvent) -> HookReply:
        return HookReply({"permission": "allow"} if ev.name == "preToolUse" else {})

    def reply_error(self, exc: Exception) -> HookReply:
        return HookReply({"permission": "allow"}, stderr=f"agentguard: hook error, allowing call: {exc}")

    def settings_path(self, user: bool, cwd: Path) -> Path:
        return (Path.home() if user else cwd) / ".cursor" / "hooks.json"

    def install(self, path: Path) -> Path:
        data = read_json(path)
        data.setdefault("version", 1)
        hooks = data.setdefault("hooks", {})
        for event in _EVENTS:
            entries = hooks.setdefault(event, [])
            if not any(e.get("command") == HOOK_COMMAND for e in entries):
                entries.append({"command": HOOK_COMMAND, "timeout": 30})
        return write_json(path, data)
