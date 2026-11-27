"""OpenAI Agents SDK: Agent Guard as tool guardrails.

    from agents import Agent, function_tool
    from agentguard.frameworks.openai_agents import guard_function_tools

    @function_tool
    def shell(command: str) -> str: ...

    agent = Agent(name="dev", tools=guard_function_tools([shell]))

Uses the SDK's own `tool_input_guardrails` / `tool_output_guardrails`: a
blocked call is rejected with `reject_content`, so the model gets Agent
Guard's reason instead of a result and the run continues. Pass
`halt_on_block=True` to raise and stop the run instead. Outputs with planted
instructions get a warning appended to what the model sees.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from ..sdk import AgentGuard, block_message

try:
    from agents import (FunctionTool, ToolGuardrailFunctionOutput, ToolInputGuardrail, ToolInputGuardrailData,
                        ToolOutputGuardrail, ToolOutputGuardrailData)
except ImportError as exc:  # pragma: no cover
    raise ImportError("agentguard.frameworks.openai_agents needs the OpenAI Agents SDK: pip install openai-agents") from exc


def _args(data: ToolInputGuardrailData) -> Any:
    raw = getattr(data.context, "tool_arguments", None)
    try:
        return json.loads(raw) if isinstance(raw, str) else (raw or {})
    except ValueError:
        return {"input": raw}


def input_guardrail(guard: AgentGuard, halt_on_block: bool = False) -> ToolInputGuardrail:
    def check(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        tool = data.context.tool_name
        args = _args(data)
        verdict = guard.check(tool, args)
        if guard.allowed(tool, args, verdict):
            return ToolGuardrailFunctionOutput.allow(output_info=verdict.to_dict())
        if halt_on_block:
            return ToolGuardrailFunctionOutput.raise_exception(output_info=verdict.to_dict())
        return ToolGuardrailFunctionOutput.reject_content(block_message(tool, verdict), output_info=verdict.to_dict())
    return ToolInputGuardrail(guardrail_function=check, name="agentguard_input")


def output_guardrail(guard: AgentGuard) -> ToolOutputGuardrail:
    def scan(data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        out = data.output if isinstance(data.output, str) else json.dumps(data.output, default=str)
        warning = guard.after(data.context.tool_name, out)
        if warning:
            return ToolGuardrailFunctionOutput.reject_content(f"{out}\n\n{warning}", output_info={"injection": True})
        return ToolGuardrailFunctionOutput.allow()
    return ToolOutputGuardrail(guardrail_function=scan, name="agentguard_output")


def guard_function_tools(tools: Sequence[FunctionTool], guard: AgentGuard | None = None, *,
                         halt_on_block: bool = False, **guard_kwargs: Any) -> list[FunctionTool]:
    """Attach Agent Guard's guardrails to each FunctionTool (in place) and return the list."""
    guard = guard or AgentGuard(agent="openai-agents", **guard_kwargs)
    ig, og = input_guardrail(guard, halt_on_block), output_guardrail(guard)
    for t in tools:
        t.tool_input_guardrails = [*(t.tool_input_guardrails or []), ig]
        t.tool_output_guardrails = [*(t.tool_output_guardrails or []), og]
    return list(tools)
