"""CrewAI: Agent Guard as global before/after tool-call hooks.

    from agentguard.frameworks.crewai import install
    install(session_id="crew-run-1")      # every tool call in every crew is now checked
    crew.kickoff()

CrewAI's before_tool_call hooks can only allow or block (return False), so a
blocked call is reported through CrewAI's own "blocked by hook" message;
Agent Guard's reason is in the audit log (`agentguard log tail`). The after
hook appends a warning to tool output that contains planted instructions.
"""

from __future__ import annotations

from typing import Any

from ..sdk import AgentGuard

try:
    from crewai.hooks import (ToolCallHookContext, register_after_tool_call_hook, register_before_tool_call_hook,
                              unregister_after_tool_call_hook, unregister_before_tool_call_hook)
except ImportError as exc:  # pragma: no cover
    raise ImportError("agentguard.frameworks.crewai needs CrewAI 1.x: pip install crewai") from exc


class CrewAIGuard:
    def __init__(self, guard: AgentGuard) -> None:
        self.guard = guard
        self.last_block: str | None = None

    def before(self, ctx: ToolCallHookContext) -> bool | None:
        args = dict(ctx.tool_input or {})
        verdict = self.guard.check(ctx.tool_name, args)
        if self.guard.allowed(ctx.tool_name, args, verdict):
            return None
        self.last_block = verdict.summary()
        return False

    def after(self, ctx: ToolCallHookContext) -> str | None:
        if ctx.tool_result is None:
            return None
        warning = self.guard.after(ctx.tool_name, str(ctx.tool_result))
        return f"{ctx.tool_result}\n\n{warning}" if warning else None

    def uninstall(self) -> None:
        unregister_before_tool_call_hook(self.before)
        unregister_after_tool_call_hook(self.after)


def install(guard: AgentGuard | None = None, **guard_kwargs: Any) -> CrewAIGuard:
    """Register Agent Guard's hooks globally. Returns a handle with `.uninstall()`."""
    g = CrewAIGuard(guard or AgentGuard(agent="crewai", **guard_kwargs))
    register_before_tool_call_hook(g.before)
    register_after_tool_call_hook(g.after)
    return g
