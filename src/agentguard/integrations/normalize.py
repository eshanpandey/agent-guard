"""Map each coding agent's tool names and arguments onto one canonical shape.

The detectors were written against Claude Code's tool vocabulary (`Bash` with
`command`, `Write` with `file_path`/`content`, ...). Other agents name the same
actions differently: Gemini CLI calls its shell `run_shell_command` and its
edit tool `replace`, Copilot writes files with `create`, Codex edits through
`apply_patch`, OpenAI-style APIs hand us `shell` with an argv list. Rather
than teach every detector every dialect, each integration normalises here
first. Extra keys we add start with `_` only when they carry no new text
(paths and working directories), so normalising never changes what the
content detectors see.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any

# Lower-cased native tool name -> canonical (Claude Code) tool name.
_CANONICAL: dict[str, str] = {
    # shells
    "bash": "Bash", "shell": "Bash", "run_shell_command": "Bash", "run_terminal_cmd": "Bash",
    "exec_command": "Bash", "local_shell": "Bash", "powershell": "Bash", "terminal": "Bash",
    "execute_command": "Bash", "run_command": "Bash", "container.exec": "Bash",
    # file reads
    "read": "Read", "read_file": "Read", "view": "Read", "read_many_files": "Read", "open_file": "Read",
    # file writes / edits
    "write": "Write", "write_file": "Write", "create": "Write", "create_file": "Write", "write_to_file": "Write",
    "edit": "Edit", "replace": "Edit", "str_replace_editor": "Edit", "str_replace_based_edit_tool": "Edit",
    "edit_file": "Edit", "search_replace": "Edit", "multiedit": "Edit", "apply_patch": "Edit",
    "delete": "Delete", "delete_file": "Delete",
    # web
    "web_fetch": "WebFetch", "webfetch": "WebFetch", "fetch": "WebFetch",
    "web_search": "WebSearch", "google_web_search": "WebSearch", "websearch": "WebSearch",
    # search
    "grep": "Grep", "grep_search": "Grep", "rg": "Grep", "glob": "Glob", "list_directory": "LS", "ls": "LS",
}

_PATCH_FILE = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$", re.M)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "powershell", "pwsh", "cmd"}


def canonical_tool(name: str) -> str:
    """Canonical tool name. MCP tools and unknown tools keep their own name."""
    return _CANONICAL.get(name.strip().lower(), name)


def parse_args(raw: Any) -> dict[str, Any]:
    """Tool arguments arrive as a dict, a JSON string, or a bare string."""
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
        except ValueError:
            return {"input": raw}
        return dict(val) if isinstance(val, dict) else {"input": raw}
    if raw is None:
        return {}
    return {"input": raw}


def _argv_to_command(argv: list[Any]) -> str:
    parts = [str(a) for a in argv]
    # ["bash", "-lc", "rm -rf ~"] -> "rm -rf ~"
    if len(parts) >= 3 and parts[0] in _SHELL_WRAPPERS and parts[1] in ("-c", "-lc", "-ic", "/c", "-Command"):
        return parts[2]
    return shlex.join(parts)


def normalize(name: str, raw_args: Any) -> tuple[str, dict[str, Any]]:
    """Return (canonical tool name, arguments with canonical keys added)."""
    tool = canonical_tool(name)
    args = parse_args(raw_args)

    if tool == "Bash":
        cmd = args.get("command", args.get("cmd", args.get("input")))
        if isinstance(cmd, list):
            cmd = _argv_to_command(cmd)
        if isinstance(cmd, str):
            args["command"] = cmd
        for key in ("working_directory", "workdir", "dir_path", "cwd"):
            if isinstance(args.get(key), str):
                args.setdefault("_cwd", args[key])
                break

    if name.strip().lower() == "apply_patch":
        # Codex sends the patch as `command` (hooks) or `input` (API); paths are inside it.
        patch = args.get("command") or args.get("input") or args.get("patch") or ""
        if isinstance(patch, list):
            patch = "\n".join(map(str, patch))
        args.pop("command", None)  # a patch is not a shell command
        args["patch"] = patch
        paths = _PATCH_FILE.findall(patch) if isinstance(patch, str) else []
        if paths:
            args.setdefault("file_path", paths[0].strip())
            if len(paths) > 1:
                args["_other_paths"] = [p.strip() for p in paths[1:]]

    if tool in ("Write", "Edit", "Read", "Delete"):
        for key in ("path", "target_file", "absolute_path", "filePath"):
            if isinstance(args.get(key), str):
                args.setdefault("file_path", args[key])
                break
        for key in ("contents", "file_text", "code_edit", "newText"):
            if isinstance(args.get(key), str):
                args.setdefault("content", args[key])
                break

    if tool == "WebFetch" and "url" not in args:
        for key in ("prompt", "input"):
            m = re.search(r"https?://\S+", str(args.get(key, "")))
            if m:
                args["url"] = m.group(0)
                break

    return tool, args


def call_cwd(args: dict[str, Any], default: str | None) -> str | None:
    return args.get("_cwd") or default
