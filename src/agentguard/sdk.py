"""Use Agent Guard from your own agent code.

    from agentguard.sdk import AgentGuard, ToolBlocked

    guard = AgentGuard(session_id="run-42")
    guard.user("Tidy up the build folder")          # what the user actually asked for

    @guard.tool                                     # checks before, scans output after
    def shell(command: str) -> str:
        ...

    shell(command="rm -rf ~")                      # raises ToolBlocked

The framework adapters in `agentguard.frameworks` (LangChain / LangGraph,
OpenAI Agents SDK, CrewAI) are thin layers over this class.
"""

from __future__ import annotations

import functools
import inspect
import uuid
from typing import Any, Callable, TypeVar

from .audit import AuditLog
from .engine import Engine
from .integrations.hooks_base import injection_warning
from .integrations.normalize import normalize
from .models import Decision, ToolCall, Verdict
from .policy import Policy, load as load_policy
from .state import MemoryStateStore

F = TypeVar("F", bound=Callable[..., Any])


class ToolBlocked(Exception):
    """Raised when Agent Guard stops a tool call."""

    def __init__(self, tool: str, verdict: Verdict) -> None:
        self.tool = tool
        self.verdict = verdict
        super().__init__(block_message(tool, verdict))


def block_message(tool: str, verdict: Verdict) -> str:
    return (f"Agent Guard blocked `{tool}`: {verdict.summary()}. The call was not run. "
            "Do not retry it in another form; tell the user what you wanted to do and let them decide.")


class AgentGuard:
    """One guarded agent session: policy + detectors + session state + audit log.

    `on_ask` decides what happens when the policy says a human should confirm:
    "block" (default; code has no human to ask), "allow" (record it as a flag),
    or a callable `(tool, args, verdict) -> bool` that asks someone and returns
    True to let the call run.
    """

    def __init__(self, policy: Policy | str | None = None, session_id: str | None = None, agent: str = "sdk",
                 audit: AuditLog | bool = True, on_ask: str | Callable[[str, dict, Verdict], bool] = "block",
                 engine: Engine | None = None) -> None:
        if engine is None:
            pol = policy if isinstance(policy, Policy) else load_policy(policy)
            log = audit if isinstance(audit, AuditLog) else (AuditLog() if audit else None)
            engine = Engine(pol, MemoryStateStore(), log)
        self.engine = engine
        self.session_id = session_id or f"{agent}-{uuid.uuid4().hex[:8]}"
        self.agent = agent
        self.on_ask = on_ask

    # -- core calls ----------------------------------------------------------
    def _call(self, tool: str, args: Any) -> ToolCall:
        canon, norm = normalize(tool, args)
        return ToolCall(canon, norm, session_id=self.session_id, agent=self.agent)

    def user(self, prompt: str) -> None:
        """Record the user's request as trusted intent."""
        self.engine.observe_user(self.session_id, prompt)

    def check(self, tool: str, args: Any = None) -> Verdict:
        """Evaluate a tool call without raising. Use `allowed()` to act on it."""
        return self.engine.evaluate(self._call(tool, args or {}))

    def allowed(self, tool: str, args: Any, verdict: Verdict) -> bool:
        if verdict.decision == Decision.BLOCK:
            return False
        if verdict.decision == Decision.ASK:
            if callable(self.on_ask):
                return bool(self.on_ask(tool, args if isinstance(args, dict) else {"input": args}, verdict))
            return self.on_ask == "allow"
        return True

    def before(self, tool: str, args: Any = None) -> Verdict:
        """Evaluate and raise ToolBlocked if the call must not run."""
        verdict = self.check(tool, args)
        if not self.allowed(tool, args, verdict):
            raise ToolBlocked(tool, verdict)
        return verdict

    def after(self, tool: str, result: Any) -> str | None:
        """Scan a tool's output. Returns a warning to show the model if it holds planted instructions."""
        verdict = self.engine.observe(self._call(tool, {}), result)
        return injection_warning(verdict) if verdict.findings else None

    # -- decorator -----------------------------------------------------------
    def tool(self, fn: F | None = None, *, name: str | None = None, warn_in_output: bool = True) -> Any:
        """Wrap a function (sync or async) so every call is checked first and its output scanned."""
        def wrap(f: F) -> F:
            tool_name = name or f.__name__
            sig = inspect.signature(f)

            def bound_args(*a: Any, **kw: Any) -> dict[str, Any]:
                try:
                    b = sig.bind_partial(*a, **kw)
                    return dict(b.arguments)
                except TypeError:
                    return {"args": list(a), **kw}

            def finish(result: Any) -> Any:
                warning = self.after(tool_name, result)
                if warning and warn_in_output and isinstance(result, str):
                    return f"{result}\n\n{warning}"
                return result

            if inspect.iscoroutinefunction(f):
                @functools.wraps(f)
                async def awrapper(*a: Any, **kw: Any) -> Any:
                    self.before(tool_name, bound_args(*a, **kw))
                    return finish(await f(*a, **kw))
                return awrapper  # type: ignore[return-value]

            @functools.wraps(f)
            def wrapper(*a: Any, **kw: Any) -> Any:
                self.before(tool_name, bound_args(*a, **kw))
                return finish(f(*a, **kw))
            return wrapper  # type: ignore[return-value]

        return wrap(fn) if fn is not None else wrap
