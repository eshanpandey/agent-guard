"""R-Judge (Yuan et al., EMNLP Findings 2024) -> traces.

R-Judge records are multi-turn agent interactions labelled safe (0) or unsafe (1)
by humans. Actions are free text in several formats; we parse each into a tool
name and arguments. Agent turns that are plain replies to the user (no tool) are
kept as a pseudo tool "respond" so the trace stays complete. Only the record
label is known, so evaluation is at record level.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from common import Step, Trace, split_of

ROOT = Path(__file__).resolve().parents[1] / ".data" / "R-Judge" / "data"

_NAMED = re.compile(r"^\s*(?:Action:\s*)?([A-Za-z][A-Za-z0-9_]{2,})\s*(?:\n\s*Action Input:\s*|:\s*|\s*(?=[\{\(]))(.*)$", re.S)
_CMD = re.compile(r'"command"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"\s*,\s*"args"\s*:\s*(\{.*\})', re.S)
_UI = re.compile(r"^\s*(click|type|open|input|swipe|tap|press)\b\s*(.*)$", re.I | re.S)


def _parse_args(text: str) -> dict:
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        inner = text[1:-1]
        try:
            node = ast.parse(f"f({inner})", mode="eval").body
            if isinstance(node, ast.Call) and node.keywords:
                return {k.arg: ast.literal_eval(k.value) for k in node.keywords if k.arg}
        except Exception:
            return {"input": inner}
    for parse in (json.loads, ast.literal_eval):
        try:
            v = parse(text)
            return v if isinstance(v, dict) else {"input": v}
        except Exception:
            pass
    return {"input": text} if text else {}


def parse_action(action: str) -> tuple[str, dict]:
    if m := _CMD.search(action):
        raw = m.group(2).strip()
        while raw.endswith("}}"):  # the outer JSON object's closing braces
            parsed = _parse_args(raw)
            if "input" not in parsed:
                return m.group(1), parsed
            raw = raw[:-1]
        return m.group(1), _parse_args(raw)
    if action.strip().startswith("Final Answer"):
        return "respond", {"text": action.split(":", 1)[-1].strip()}
    if m := _UI.match(action):
        return m.group(1).lower(), {"target": m.group(2).strip()}
    if m := _NAMED.match(action):
        name, rest = m.group(1), m.group(2)
        if rest.strip()[:1] in "{(" or "Action Input" in action or re.match(r"^[A-Z]\w+$", name):
            return name, _parse_args(rest)
    return "respond", {"text": action.strip()}


def load() -> list[Trace]:
    traces: list[Trace] = []
    for path in sorted(ROOT.glob("*/*.json")):
        for rec in json.loads(path.read_text()):
            steps: list[Step] = []
            user_prompt = next((m["content"] for turn in rec["contents"] for m in turn if m["role"] == "user"), "")
            for turn in rec["contents"]:
                for m in turn:
                    if m["role"] == "agent":
                        action = m.get("action") or ""
                        if action.strip():
                            tool, args = parse_action(action)
                            # Plain replies to the user are not tool calls; a runtime
                            # guard never sees them, so they are left out.
                            if tool != "respond":
                                steps.append(Step(tool, args, None, None))
                    elif m["role"] == "environment" and steps and m.get("content"):
                        steps[-1].result = m["content"]
            key = f"{path.parent.name}/{path.stem}/{rec['id']}"
            traces.append(Trace(f"rjudge/{key}", "rjudge", split_of("rjudge:" + key), int(rec["label"]), steps,
                                {"category": path.parent.name, "scenario": rec.get("scenario"), "attack_type": rec.get("attack_type"),
                                 "user_prompt": user_prompt}))
    return traces
