"""Incident replay benchmark.

Replays scenario files (real incidents rebuilt as tool-call traces, plus normal
sessions) through the engine and reports detection and false-positive rates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .engine import Engine
from .models import Finding, Severity, ToolCall
from .policy import from_dict
from .state import MemoryStateStore

WORKSPACE = "/workspace/project"


@dataclass
class ScenarioResult:
    id: str
    title: str
    kind: str
    passed: bool
    max_severity: Severity | None
    expected: str
    fired_rules: list[str] = field(default_factory=list)
    missing_rules: list[str] = field(default_factory=list)
    first_alert_step: int | None = None
    findings: list[Finding] = field(default_factory=list)


def load_scenarios(paths: list[str] | None = None) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    if paths:
        files = []
        for p in paths:
            path = Path(p)
            files.extend(sorted(path.glob("*.y*ml")) if path.is_dir() else [path])
        texts = [f.read_text() for f in files]
    else:
        folder = resources.files("agentguard").joinpath("scenarios")
        texts = [f.read_text() for f in sorted(folder.iterdir(), key=lambda f: f.name) if f.name.endswith(".yaml")]
    for text in texts:
        data = yaml.safe_load(text)
        docs.extend(data if isinstance(data, list) else [data])
    return docs


def _fill(value: Any, i: int) -> Any:
    if isinstance(value, str):
        return value.replace("{i}", str(i))
    if isinstance(value, dict):
        return {k: _fill(v, i) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, i) for v in value]
    return value


def run_scenario(sc: dict[str, Any]) -> ScenarioResult:
    kind = sc.get("kind", "attack")
    policy = from_dict({"workspace": WORKSPACE, **(sc.get("policy") or {})})
    engine = Engine(policy, MemoryStateStore())
    session = f"replay-{sc['id']}"
    t = 1_700_000_000.0
    findings: list[Finding] = []
    first_alert = None
    alert_floor = Severity.MEDIUM
    step_no = 0

    for step in sc.get("steps", []):
        for i in range(int(step.get("repeat", 1))):
            step_no += 1
            t += 1.0
            spec = _fill(step["call"], i)
            call = ToolCall(tool=spec["tool"], args=spec.get("args") or {}, session_id=session,
                            agent="replay", cwd=WORKSPACE, timestamp=t)
            verdict = engine.evaluate(call)
            findings.extend(verdict.findings)
            if first_alert is None and any(f.severity >= alert_floor for f in verdict.findings):
                first_alert = step_no
            if "result" in step:
                obs = engine.observe(call, _fill(step["result"], i))
                findings.extend(obs.findings)
                if first_alert is None and any(f.severity >= alert_floor for f in obs.findings):
                    first_alert = step_no

    top = max((f.severity for f in findings), default=None)
    fired = sorted({f.rule_id for f in findings})
    if kind == "benign":
        passed = top is None or top < Severity.MEDIUM
        return ScenarioResult(sc["id"], sc.get("title", ""), kind, passed, top, "below medium", fired, [], first_alert, findings)

    expect = sc.get("expect") or {}
    floor = Severity.parse(expect.get("min_severity", "medium"))
    wanted = list(expect.get("rules") or [])
    missing = [r for r in wanted if r not in fired]
    passed = top is not None and top >= floor and not missing
    return ScenarioResult(sc["id"], sc.get("title", ""), kind, passed, top, f">= {floor}", fired, missing, first_alert, findings)


def run_all(paths: list[str] | None = None) -> list[ScenarioResult]:
    return [run_scenario(sc) for sc in load_scenarios(paths)]


def summarize(results: list[ScenarioResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.kind != "benign"]
    benign = [r for r in results if r.kind == "benign"]
    return {
        "attacks": len(attacks),
        "detected": sum(r.passed for r in attacks),
        "benign": len(benign),
        "false_positives": sum(not r.passed for r in benign),
    }
