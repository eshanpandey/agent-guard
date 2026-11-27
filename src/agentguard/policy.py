"""Policy loading. A policy is a YAML file merged over the bundled defaults."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import Severity

MODES = ("monitor", "guard", "enforce")
POLICY_FILENAMES = (".agentguard.yaml", ".agentguard.yml", "agentguard.yaml")


@dataclass
class CustomRule:
    id: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str
    tools: re.Pattern[str] | None = None
    owasp: list[str] = field(default_factory=list)


@dataclass
class Policy:
    mode: str = "guard"
    workspace: str | None = None
    allowed_domains: list[str] = field(default_factory=list)
    allowed_email_domains: list[str] = field(default_factory=list)
    change_freeze: bool = False
    production_markers: list[str] = field(default_factory=list)
    window_seconds: int = 60
    max_calls_per_tool: int = 40
    max_messages: int = 10
    max_identical_calls: int = 6
    disabled_rules: set[str] = field(default_factory=set)
    custom_rules: list[CustomRule] = field(default_factory=list)

    def domain_allowed(self, host: str) -> bool:
        host = host.lower().strip(".")
        for d in self.allowed_domains:
            d = d.lower().strip(".")
            if host == d or host.endswith("." + d):
                return True
        return False

    def email_domain_allowed(self, domain: str) -> bool:
        domain = domain.lower()
        return any(domain == d.lower() or domain.endswith("." + d.lower()) for d in self.allowed_email_domains)


def _default_dict() -> dict[str, Any]:
    text = resources.files("agentguard").joinpath("default_policy.yaml").read_text()
    return yaml.safe_load(text) or {}


def from_dict(data: dict[str, Any]) -> Policy:
    merged = _default_dict()
    for key, value in (data or {}).items():
        if key == "rate_limits" and isinstance(value, dict):
            merged.setdefault("rate_limits", {}).update(value)
        else:
            merged[key] = value

    mode = str(merged.get("mode", "guard")).lower()
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}, got {mode!r}")

    rl = merged.get("rate_limits") or {}
    custom = []
    for raw in merged.get("custom_rules") or []:
        custom.append(
            CustomRule(
                id=str(raw["id"]),
                pattern=re.compile(raw["pattern"]),
                severity=Severity.parse(raw.get("severity", "medium")),
                message=str(raw.get("message", raw["id"])),
                tools=re.compile(raw["tools"]) if raw.get("tools") else None,
                owasp=list(raw.get("owasp") or []),
            )
        )
    return Policy(
        mode=mode,
        workspace=merged.get("workspace"),
        allowed_domains=list(merged.get("allowed_domains") or []),
        allowed_email_domains=list(merged.get("allowed_email_domains") or []),
        change_freeze=bool(merged.get("change_freeze", False)),
        production_markers=list(merged.get("production_markers") or []),
        window_seconds=int(rl.get("window_seconds", 60)),
        max_calls_per_tool=int(rl.get("max_calls_per_tool", 40)),
        max_messages=int(rl.get("max_messages", 10)),
        max_identical_calls=int(rl.get("max_identical_calls", 6)),
        disabled_rules=set(merged.get("disabled_rules") or []),
        custom_rules=custom,
    )


def load(path: str | os.PathLike[str] | None = None, search_from: str | None = None) -> Policy:
    """Load a policy file, or find one in `search_from` and its parents, or use defaults."""
    if path:
        return from_dict(yaml.safe_load(Path(path).read_text()) or {})
    env = os.environ.get("AGENTGUARD_POLICY")
    if env:
        return from_dict(yaml.safe_load(Path(env).read_text()) or {})
    start = Path(search_from or os.getcwd()).resolve()
    for folder in (start, *start.parents):
        for name in POLICY_FILENAMES:
            candidate = folder / name
            if candidate.is_file():
                return from_dict(yaml.safe_load(candidate.read_text()) or {})
    return from_dict({})


def default_policy_text() -> str:
    return resources.files("agentguard").joinpath("default_policy.yaml").read_text()
