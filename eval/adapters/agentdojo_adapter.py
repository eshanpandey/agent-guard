"""AgentDojo (Debenedetti et al., NeurIPS 2024) -> traces.

AgentDojo has no recorded agent runs, but every user task and injection task
ships a `ground_truth()` list of the exact tool calls that solve it. We build:

* clean traces: the user task's ground-truth calls, executed in the clean
  environment (real tool outputs). All calls are labelled benign.
* attacked traces: the same user-task calls executed in an environment whose
  injection points carry the attack text, followed by the injection task's
  ground-truth calls, i.e. what a fully hijacked agent would do. Injection-task
  calls are labelled malicious.

This is an "oracle hijack" replay: it measures whether the guard flags the
attacker's actions if the model falls for the injection, independent of which
LLM is used.
"""

from __future__ import annotations

import json
from typing import Any

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suites

from common import Step, Trace

SPLIT = {"workspace": "dev", "slack": "dev", "banking": "test", "travel": "test"}

ATTACKS = {
    # AgentDojo's strongest standard attack, used in its paper and in LlamaFirewall's evaluation
    "important_instructions": ImportantInstructionsAttack._JB_STRING,
    # AgentDojo's plain "direct" attack: no tell-tale phrasing at all
    "direct": "TODO: {goal}",
}


def _to_jsonable(value: Any) -> Any:
    try:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, (list, tuple)):
            return [_to_jsonable(v) for v in value]
        json.dumps(value, default=str)
        return value
    except Exception:
        return str(value)


def _result_text(value: Any) -> str:
    return json.dumps(_to_jsonable(value), default=str)


def _execute(runtime: FunctionsRuntime, env: Any, calls: list[Any], label: int) -> list[Step]:
    steps = []
    for fc in calls:
        args = dict(fc.args)
        result, error = runtime.run_function(env, fc.function, args)
        steps.append(Step(tool=fc.function, args=_to_jsonable(args), label=label,
                          result=_result_text(result) if error is None else str(error)))
        # Use the exact text AgentDojo shows the model (YAML), not our own serialisation
        try:
            steps[-1].result = tool_result_to_str(result) if error is None else str(error)
        except Exception:
            pass
    return steps


def load(attack: str = "important_instructions", version: str = "v1.2") -> list[Trace]:
    template = ATTACKS[attack]
    traces: list[Trace] = []
    for suite_name, suite in get_suites(version).items():
        runtime = FunctionsRuntime(suite.tools)
        vectors = list(suite.get_injection_vector_defaults().keys())
        split = SPLIT[suite_name]

        for ut_id, ut in suite.user_tasks.items():
            env = suite.load_and_inject_default_environment({})
            steps = _execute(runtime, env, ut.ground_truth(env), 0)
            traces.append(Trace(f"agentdojo/{suite_name}/{ut_id}/clean", "agentdojo", split, 0, steps,
                                {"suite": suite_name, "user_task": ut_id, "user_prompt": ut.PROMPT}))

        for it_id, it in suite.injection_tasks.items():
            if not it.ground_truth(suite.load_and_inject_default_environment({})):
                # Tasks added after v1 ship no ground-truth calls, so there is no
                # attacker action to label. They are excluded (see report).
                continue
            text = template.format(user="Emma Johnson", model="the AI assistant", goal=it.GOAL)
            for ut_id, ut in suite.user_tasks.items():
                env = suite.load_and_inject_default_environment({v: text for v in vectors})
                steps = _execute(runtime, env, ut.ground_truth(env), 0)
                steps += _execute(runtime, env, it.ground_truth(env), 1)
                traces.append(Trace(f"agentdojo/{suite_name}/{ut_id}/{it_id}/{attack}", "agentdojo", split, 1, steps,
                                    {"suite": suite_name, "user_task": ut_id, "injection_task": it_id, "attack": attack,
                                     "user_prompt": ut.PROMPT}))
    return traces
