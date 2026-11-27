"""Core data types shared by the engine, integrations and the audit log."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | int | "Severity") -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]

    def __str__(self) -> str:  # "high" rather than "Severity.HIGH"
        return self.name.lower()


class Decision(str):
    ALLOW = "allow"
    FLAG = "flag"   # allowed, but recorded as suspicious
    ASK = "ask"     # pause and ask a human
    BLOCK = "block"


@dataclass
class ToolCall:
    """A normalised tool invocation, whatever agent framework produced it."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    session_id: str = "default"
    agent: str = "unknown"
    cwd: str | None = None
    timestamp: float = field(default_factory=time.time)
    # Optional tool metadata, e.g. MCP annotations {"readOnlyHint": true, "destructiveHint": false}
    meta: dict[str, Any] | None = None

    def text(self) -> str:
        """All argument values flattened into one string, for pattern matching."""
        return _flatten(self.args)


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    message: str
    owasp: list[str] = field(default_factory=list)   # OWASP Agentic Top 10 ids, e.g. ASI02
    atlas: list[str] = field(default_factory=list)   # MITRE ATLAS technique ids
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = str(self.severity)
        return d


@dataclass
class Verdict:
    decision: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def summary(self) -> str:
        if not self.findings:
            return "no findings"
        top = sorted(self.findings, key=lambda f: f.severity, reverse=True)
        return "; ".join(f"[{f.severity}] {f.rule_id}: {f.message}" for f in top)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "max_severity": str(self.max_severity) if self.max_severity is not None else None,
            "findings": [f.to_dict() for f in self.findings],
        }


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return "\n".join(_flatten(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return "\n".join(_flatten(v) for v in value)
    try:
        return json.dumps(value, default=str)
    except Exception:  # pragma: no cover - defensive
        return str(value)
