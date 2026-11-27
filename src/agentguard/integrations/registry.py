"""All hook-based agent integrations, by the name used on the command line."""

from __future__ import annotations

from .codex import CodexAdapter
from .copilot import CopilotAdapter
from .cursor import CursorAdapter
from .gemini_cli import GeminiAdapter
from .hooks_base import HookAdapter

ADAPTERS: dict[str, type[HookAdapter]] = {
    "cursor": CursorAdapter,
    "codex": CodexAdapter,
    "gemini": GeminiAdapter,
    "copilot": CopilotAdapter,
}


def get(name: str) -> HookAdapter:
    return ADAPTERS[name]()
