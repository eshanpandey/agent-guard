"""LangChain and LangGraph: wrap tools so every call goes through Agent Guard.

    from agentguard.frameworks.langchain import guard_tools
    tools = guard_tools([shell_tool, search_tool], session_id="run-1")
    agent = create_react_agent(model, tools)          # LangGraph, or any LangChain agent

A blocked call does not raise by default: the tool returns Agent Guard's
reason as its output, so the agent loop continues and the model sees why
(`raise_on_block=True` raises ToolBlocked instead). Outputs with planted
instructions get a warning appended.
"""

from __future__ import annotations

from typing import Any, Sequence

from ..sdk import AgentGuard, ToolBlocked

try:
    from langchain_core.tools import BaseTool
    from pydantic import ConfigDict
except ImportError as exc:  # pragma: no cover
    raise ImportError("agentguard.frameworks.langchain needs langchain-core: pip install langchain-core") from exc


class GuardedTool(BaseTool):
    """A LangChain tool that delegates to `inner` after Agent Guard approves the call."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    inner: BaseTool
    guard: Any
    raise_on_block: bool = False

    def __init__(self, inner: BaseTool, guard: AgentGuard, raise_on_block: bool = False) -> None:
        super().__init__(name=inner.name, description=inner.description, args_schema=inner.args_schema,
                         return_direct=inner.return_direct, inner=inner, guard=guard, raise_on_block=raise_on_block)

    def _check(self, kwargs: dict[str, Any]) -> str | None:
        try:
            self.guard.before(self.name, kwargs)
        except ToolBlocked as e:
            if self.raise_on_block:
                raise
            return str(e)
        return None

    def _finish(self, out: Any) -> Any:
        warning = self.guard.after(self.name, out if isinstance(out, str) else str(out))
        return f"{out}\n\n{warning}" if warning and isinstance(out, str) else out

    def _run(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
        payload = kwargs if kwargs else ({"input": args[0]} if args else {})
        if (msg := self._check(payload)) is not None:
            return msg
        return self._finish(self.inner.invoke(payload if kwargs else (args[0] if args else {})))

    async def _arun(self, *args: Any, run_manager: Any = None, **kwargs: Any) -> Any:
        payload = kwargs if kwargs else ({"input": args[0]} if args else {})
        if (msg := self._check(payload)) is not None:
            return msg
        return self._finish(await self.inner.ainvoke(payload if kwargs else (args[0] if args else {})))


def guard_tools(tools: Sequence[BaseTool], guard: AgentGuard | None = None, *, raise_on_block: bool = False,
                **guard_kwargs: Any) -> list[BaseTool]:
    """Return guarded copies of `tools` that share one Agent Guard session."""
    guard = guard or AgentGuard(agent="langchain", **guard_kwargs)
    return [GuardedTool(t, guard, raise_on_block) for t in tools]
