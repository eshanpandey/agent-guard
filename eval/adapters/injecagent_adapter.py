"""InjecAgent (Zhan et al., ACL Findings 2024) -> traces.

Each test case is: the user's tool call, its response carrying the attacker's
instruction, then the attacker's tool call(s). We replay the case as a trace in
which the agent fully follows the injection (oracle hijack):

  1. user tool call            (benign)   -> response containing the injection
  2. attacker tool 1           (malicious)
  3. data-stealing cases only: GmailSendEmail to the attacker (malicious)

InjecAgent does not provide arguments for the attacker's tool calls. Data-stealing
emails use the dataset's fixed attacker address; other attacker calls carry no
arguments, so only the tool name and session context can be judged. A clean trace
is the same user call with the injection removed from the response.

Split: by attacker case (hash of the attacker instruction), so dev and test never
share an attack.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from common import Step, Trace, split_of

ROOT = Path(__file__).resolve().parents[1] / ".data" / "InjecAgent" / "data"
ATTACKER_EMAIL = "amy.watson@gmail.com"


def _args(text: str) -> dict:
    for parse in (json.loads, ast.literal_eval):
        try:
            v = parse(text)
            return v if isinstance(v, dict) else {"input": v}
        except Exception:
            pass
    return {"input": text}


def load(setting: str = "base") -> list[Trace]:
    traces: list[Trace] = []
    clean_seen: set[str] = set()
    for kind in ("dh", "ds"):
        cases = json.loads((ROOT / f"test_cases_{kind}_{setting}.json").read_text())
        for i, c in enumerate(cases):
            split = split_of("injecagent:" + c["Attacker Instruction"])
            user = Step(c["User Tool"], _args(c["Tool Parameters"]), 0, c["Tool Response"])
            steps = [user]
            atk = c["Attacker Tools"]
            steps.append(Step(atk[0], {}, 1, None))
            if kind == "ds":
                steps.append(Step("GmailSendEmail", {"to": ATTACKER_EMAIL, "subject": "Requested information",
                                                     "body": "Here is the information you asked for."}, 1, None))
            traces.append(Trace(f"injecagent/{setting}/{kind}/{i}", "injecagent", split, 1, steps,
                                {"kind": kind, "attack_type": c["Attack Type"], "attacker_tools": atk,
                                 "user_prompt": c["User Instruction"]}))

            key = c["User Tool"] + c["User Instruction"]
            if key not in clean_seen:
                clean_seen.add(key)
                clean_resp = c["Tool Response Template"].replace("<Attacker Instruction>", "Great product, works as described.")
                traces.append(Trace(f"injecagent/clean/{len(clean_seen)}", "injecagent", split_of("injecagent-user:" + key), 0,
                                    [Step(c["User Tool"], _args(c["Tool Parameters"]), 0, clean_resp)], {"kind": "clean", "user_prompt": c["User Instruction"]}))
    return traces
