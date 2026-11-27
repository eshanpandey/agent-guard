"""Policy loading. A policy is a YAML file merged over the bundled defaults."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

try:  # PyYAML is optional so the Claude Code plugin runs on a bare Python
    import yaml
except ImportError:  # pragma: no cover - exercised in test_plugin.py via a subprocess
    yaml = None

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
    classifier: dict[str, Any] | None = None

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


def _scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    if text[0] in "\"'" and text[-1] == text[0]:
        return text[1:-1]
    low = text.lower()
    if low in ("null", "~"):
        return None
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        return [_scalar(x) for x in inner.split(",")] if inner else []
    if text == "{}":
        return {}
    try:
        return int(text)
    except ValueError:
        return text


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if ch in "\"'":
            quote = None if quote == ch else (quote or ch)
        elif ch == "#" and quote is None and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the YAML subset policies use when PyYAML is not installed.

    Handles top-level `key: value`, inline lists, `- item` block lists and one
    level of nested mappings (rate_limits). Anything else raises ValueError.
    """
    out: dict[str, Any] = {}
    parent: str | None = None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0:
            if ":" not in body:
                raise ValueError(f"cannot parse policy line without PyYAML: {raw!r}")
            key, _, value = body.partition(":")
            parent = key.strip()
            out[parent] = _scalar(value)
            continue
        if parent is None:
            raise ValueError(f"cannot parse policy line without PyYAML: {raw!r}")
        if body.startswith("- "):
            item = body[2:].strip()
            if ":" in item and not item.startswith(("'", '"')):
                raise ValueError("custom_rules and other lists of mappings need PyYAML (pip install pyyaml)")
            if not isinstance(out[parent], list):
                out[parent] = []
            out[parent].append(_scalar(item))
        elif ":" in body:
            key, _, value = body.partition(":")
            if not isinstance(out[parent], dict):
                out[parent] = {}
            out[parent][key.strip()] = _scalar(value)
        else:
            raise ValueError(f"cannot parse policy line without PyYAML: {raw!r}")
    return out


def parse_text(text: str) -> dict[str, Any]:
    """Parse policy text with PyYAML when available, else JSON or a simple YAML subset."""
    if yaml is not None:
        return yaml.safe_load(text) or {}
    stripped = text.strip()
    if stripped.startswith("{"):
        return json.loads(stripped)
    return _parse_simple_yaml(text)


def _read(path: Path) -> dict[str, Any]:
    try:
        return parse_text(path.read_text())
    except ValueError as exc:
        if yaml is not None:
            raise
        # Without PyYAML we keep protecting the user with the defaults rather
        # than failing open, and say why on stderr.
        print(f"agentguard: could not read {path} ({exc}); using the default policy", file=sys.stderr)
        return {}


def _default_dict() -> dict[str, Any]:
    return parse_text(default_policy_text())


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
        classifier=merged.get("classifier") or None,
    )


def load(path: str | os.PathLike[str] | None = None, search_from: str | None = None) -> Policy:
    """Load a policy file, or find one in `search_from` and its parents, or use defaults."""
    if path:
        return from_dict(_read(Path(path)))
    env = os.environ.get("AGENTGUARD_POLICY")
    if env:
        return from_dict(_read(Path(env)))
    start = Path(search_from or os.getcwd()).resolve()
    for folder in (start, *start.parents):
        for name in POLICY_FILENAMES:
            candidate = folder / name
            if candidate.is_file():
                return from_dict(_read(candidate))
    return from_dict({})


def default_policy_text() -> str:
    return resources.files("agentguard").joinpath("default_policy.yaml").read_text()
