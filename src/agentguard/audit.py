"""Tamper-evident audit log.

Each line is a JSON record holding the hash of the previous record, so editing
or deleting any past line breaks the chain and `verify()` reports where.
Secrets in tool arguments are masked before they are written.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

if TYPE_CHECKING:
    from .models import ToolCall, Verdict

GENESIS = "0" * 64

_SECRETS = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_-]{20,}"
    r"|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|npm_[A-Za-z0-9]{36}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)"
)
_MAX_FIELD = 4000


def home() -> Path:
    return Path(os.environ.get("AGENTGUARD_HOME", Path.home() / ".agentguard"))


def redact(value: Any) -> Any:
    if isinstance(value, str):
        masked = _SECRETS.sub(lambda m: m.group(0)[:6] + "***REDACTED***", value)
        return masked if len(masked) <= _MAX_FIELD else masked[:_MAX_FIELD] + "...[truncated]"
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def _hash(prev: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    lock = path.with_suffix(path.suffix + ".lock")
    with open(lock, "a") as fh:
        try:
            import fcntl
            fcntl.flock(fh, fcntl.LOCK_EX)
        except ImportError:  # Windows: best effort
            pass
        yield


class AuditLog:
    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        self.path = Path(path) if path else home() / "audit.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        with open(self.path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            block = min(size, 65536)
            fh.seek(size - block)
            lines = fh.read().splitlines()
        for line in reversed(lines):
            if line.strip():
                return json.loads(line)["hash"]
        return GENESIS

    def append(self, event: str, call: "ToolCall", verdict: "Verdict") -> dict[str, Any]:
        body = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(call.timestamp)),
            "event": event,
            "session": call.session_id,
            "agent": call.agent,
            "tool": call.tool,
            "args": redact(call.args),
            **verdict.to_dict(),
        }
        with _locked(self.path):
            prev = self._last_hash()
            record = {**body, "prev": prev, "hash": _hash(prev, body)}
            with open(self.path, "a") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        return record

    def records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path) as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def verify(self) -> tuple[bool, int, str]:
        """Return (ok, records_checked, message)."""
        prev = GENESIS
        n = 0
        for n, rec in enumerate(self.records(), start=1):
            body = {k: v for k, v in rec.items() if k not in ("prev", "hash")}
            if rec.get("prev") != prev:
                return False, n, f"record {n}: chain broken (a record before it was removed or reordered)"
            if _hash(prev, body) != rec.get("hash"):
                return False, n, f"record {n}: contents were modified after logging"
            prev = rec["hash"]
        return True, n, f"{n} records, chain intact"
