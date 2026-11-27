"""Google Gemini CLI integration via hooks in settings.json.

Gemini CLI fires `BeforeTool` and `AfterTool` around every tool, and
`BeforeAgent` when the user submits a prompt. Built-in tools are snake_case
(`run_shell_command`, `write_file`, `replace`, `read_file`, `web_fetch`, ...);
MCP tools are `mcp_<server>_<tool>`. A tool is stopped with
`{"decision": "deny", "reason": ...}`; the reason goes back to the model as the
tool's error and the turn continues.

Gemini CLI hooks have no "ask" decision, so calls our policy would ask about
are denied with a reason asking the agent to get the user's go-ahead.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..models import Decision, Verdict
from .hooks_base import (POST, PRE, PROMPT, SKIP, HookAdapter, HookEvent, HookReply, add_nested_hook,
                         blocks, injection_warning, make_call, read_json, reason, write_json)

HOOK_COMMAND = "agentguard hook gemini"
_ENV_VARS = ("AGENTGUARD_HOME", "AGENTGUARD_POLICY")


def _result_text(resp: Any) -> Any:
    if isinstance(resp, dict):
        parts = [resp.get("llmContent"), resp.get("error")]
        parts = [p for p in parts if p]
        if parts:
            return parts[0] if len(parts) == 1 and isinstance(parts[0], str) else parts
    return resp


class GeminiAdapter(HookAdapter):
    agent = "gemini-cli"
    post_install_note = ("Gemini CLI asks you to trust new project hooks the first time; check them with "
                         "/hooks panel.")

    def parse(self, event: dict[str, Any]) -> HookEvent:
        name = str(event.get("hook_event_name", ""))
        session, cwd = event.get("session_id"), event.get("cwd")
        if name == "BeforeAgent":
            return HookEvent(PROMPT, make_call(self.agent, "prompt", {}, session, cwd),
                             prompt=str(event.get("prompt", "")), raw=event, name=name)
        if name in ("BeforeTool", "AfterTool"):
            call = make_call(self.agent, str(event.get("tool_name", "unknown")), event.get("tool_input"), session, cwd)
            kind = PRE if name == "BeforeTool" else POST
            return HookEvent(kind, call, result=_result_text(event.get("tool_response")), raw=event, name=name)
        return HookEvent(SKIP, raw=event, name=name)

    # Gemini parses stdout as JSON on exit 0, so always print an object.
    def reply_pre(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not blocks(verdict):
            return HookReply({})
        why = reason(verdict)
        if verdict.decision == Decision.ASK:
            why += (" (needs the user's confirmation; Gemini CLI hooks cannot ask, so the call was stopped. "
                    "Tell the user what you wanted to do and why, and let them approve it.)")
        return HookReply({"decision": "deny", "reason": why, "systemMessage": why})

    def reply_post(self, verdict: Verdict, ev: HookEvent) -> HookReply:
        if not verdict.findings:
            return HookReply({})
        return HookReply({"hookSpecificOutput": {"hookEventName": "AfterTool",
                                                 "additionalContext": injection_warning(verdict)}})

    def reply_prompt(self, ev: HookEvent) -> HookReply:
        return HookReply({})

    def reply_skip(self, ev: HookEvent) -> HookReply:
        return HookReply({})

    def reply_error(self, exc: Exception) -> HookReply:
        return HookReply({}, stderr=f"agentguard: hook error, allowing call: {exc}")

    def settings_path(self, user: bool, cwd: Path) -> Path:
        return (Path.home() if user else cwd) / ".gemini" / "settings.json"

    def install(self, path: Path) -> Path:
        data = read_json(path)
        hooks = data.setdefault("hooks", {})
        extra = {"name": "agent-guard", "timeout": 30000, "description": "Agent Guard runtime checks"}
        add_nested_hook(hooks, "BeforeAgent", HOOK_COMMAND, None, extra)
        add_nested_hook(hooks, "BeforeTool", HOOK_COMMAND, ".*", extra)
        add_nested_hook(hooks, "AfterTool", HOOK_COMMAND, ".*", extra)
        # Gemini CLI strips non-allowlisted environment variables from hook
        # processes when redaction is on, and always under GitHub Actions
        # (GITHUB_SHA set). Keep Agent Guard's own settings visible to the hook.
        redaction = data.setdefault("security", {}).setdefault("environmentVariableRedaction", {})
        allowed = redaction.setdefault("allowed", [])
        for var in _ENV_VARS:
            if var not in allowed:
                allowed.append(var)
        return write_json(path, data)
