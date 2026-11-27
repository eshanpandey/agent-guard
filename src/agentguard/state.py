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

# Words too common to show the user pointed at a specific document
_GENERIC = {"file", "files", "txt", "pdf", "doc", "docs", "document", "email", "emails", "message", "messages", "data",
            "path", "name", "home", "user", "users", "the", "and", "for", "from", "get", "read", "list", "all"}

# Action words that are usually nouns in a request ("my latest email") and so don't show intent
_NOUNISH = {"email", "mail", "post", "order", "payment", "run", "write", "change", "update", "add", "share", "lock"}

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
    # Instructions found in tool output: {"strength", "source", "entities", "tokens"}
    data_instructions: list[dict] = field(default_factory=list)
    # What the user asked for, when the integration can see the prompt
    user_entities: list[str] = field(default_factory=list)
    user_tokens: list[str] = field(default_factory=list)
    user_identifiers: list[str] = field(default_factory=list)
    user_text: str = ""
    # Entities (accounts, emails, domains) seen in tool output that carried no instructions
    clean_entities: list[str] = field(default_factory=list)

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


    def add_instruction(self, strength: str, source: str, entities: set[str], tokens: set[str],
                        source_ref: list[str] | None = None, doc_entities: int = 0) -> None:
        # source_ref: entities and words of the call that produced the output (e.g. a file name),
        # used to tell whether the user pointed the agent at that document.
        self.data_instructions = (self.data_instructions + [
            {"strength": strength, "source": source, "entities": sorted(entities), "tokens": sorted(tokens),
             "source_ref": source_ref or [], "doc_entities": doc_entities}])[-_MAX_CALLS:]

    def add_clean_entities(self, entities: set[str]) -> None:
        self.clean_entities = sorted(set(self.clean_entities) | entities)[-2000:]

    def instruction_entities(self, exclude_user_pointed: bool = False) -> set[str]:
        """Entities found inside instructions in tool output.

        With exclude_user_pointed, skip weak instructions from a document the user
        explicitly named (e.g. 'pay the bill in bill-december.txt'): following those
        is what the user asked for.
        """
        out: set[str] = set()
        for ins in self.data_instructions:
            if not (exclude_user_pointed and self.user_pointed(ins)):
                out |= set(ins["entities"])
        return out

    def user_pointed(self, ins: dict) -> bool:
        """A weak instruction from a document the user explicitly named in their request."""
        from .provenance import ACTION_WORDS, stem
        named = set(self.user_identifiers)
        if ins["strength"] != "weak" or not (set(ins.get("source_ref", [])) & named):
            return False
        # A document naming several accounts or addresses is ambiguous (one may be planted):
        # only a document with a single one counts as pointing the agent at it.
        if ins.get("doc_entities", 0) > 1:
            return False
        # ...and the document asks for the same kind of action the user asked for
        # ("pay the bill in bill.txt" -> the bill says "please pay to IBAN ...").
        actions = {stem(w) for w in ACTION_WORDS - _NOUNISH}
        return bool({stem(w) for w in ins["tokens"]} & {stem(w) for w in self.user_tokens} & actions)

    def add_user_intent(self, entities: set[str], tokens: set[str], identifiers: set[str] | None = None) -> None:
        self.user_entities = sorted(set(self.user_entities) | entities)
        self.user_tokens = sorted(set(self.user_tokens) | tokens)
        self.user_identifiers = sorted(set(self.user_identifiers) | (identifiers or set()))


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

    def lock(self, session_id: str):
        from .audit import _locked
        return _locked(self._path(session_id))

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
