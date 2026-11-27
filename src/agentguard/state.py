"""Per-session memory: taint, recent calls and rate counters.

Hook-based integrations start a new process for every tool call, so state can
be kept on disk (FileStateStore) as well as in memory (MemoryStateStore).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .models import ToolCall

_MAX_TIMES = 500
_MAX_CALLS = 50


@dataclass
class SessionState:
    taint: str = "none"            # none | untrusted | injected
    taint_source: str = ""
    secret_touched: bool = False
    tool_times: dict[str, list[float]] = field(default_factory=dict)
    message_times: list[float] = field(default_factory=list)
    last_calls: list[str] = field(default_factory=list)

    @staticmethod
    def signature(call: ToolCall) -> str:
        raw = call.tool + "\0" + json.dumps(call.args, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def record(self, call: ToolCall, is_message: bool, window: float) -> None:
        now = call.timestamp
        times = [t for t in self.tool_times.get(call.tool, []) if now - t <= window]
        times.append(now)
        self.tool_times[call.tool] = times[-_MAX_TIMES:]
        if is_message:
            self.message_times = [t for t in self.message_times if now - t <= window][-_MAX_TIMES:] + [now]
        self.last_calls = (self.last_calls + [self.signature(call)])[-_MAX_CALLS:]

    def taint_with(self, level: str, source: str) -> None:
        order = {"none": 0, "untrusted": 1, "injected": 2}
        if order[level] > order[self.taint]:
            self.taint, self.taint_source = level, source


class MemoryStateStore:
    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def load(self, session_id: str) -> SessionState:
        return self._states.setdefault(session_id, SessionState())

    def save(self, session_id: str, state: SessionState) -> None:
        self._states[session_id] = state


class FileStateStore:
    def __init__(self, folder: str | os.PathLike[str]) -> None:
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", session_id)[:120] or "default"
        return self.folder / f"{safe}.json"

    def load(self, session_id: str) -> SessionState:
        p = self._path(session_id)
        if not p.exists():
            return SessionState()
        try:
            return SessionState(**json.loads(p.read_text()))
        except (ValueError, TypeError):
            return SessionState()

    def save(self, session_id: str, state: SessionState) -> None:
        p = self._path(session_id)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(state)))
        os.replace(tmp, p)
