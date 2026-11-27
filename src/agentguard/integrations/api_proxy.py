"""LLM API proxy: guard any agent by sitting between it and its model API.

Every coding agent, whatever its hooks, ends up sending HTTP requests to a
model API and executing the tool calls in the response. This proxy speaks the
OpenAI (Chat Completions and Responses), Anthropic Messages and Gemini
generateContent formats. Point the agent's base URL at it:

    agentguard api-proxy --port 8787
    export OPENAI_BASE_URL=http://127.0.0.1:8787/v1        # OpenAI SDKs, Codex, Aider, ...
    export ANTHROPIC_BASE_URL=http://127.0.0.1:8787        # Anthropic SDKs, Claude Code
    export GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8787    # Gemini CLI

On the way back, every tool call in the model's response is evaluated before
the agent ever sees it. A blocked call is removed from the response and
replaced with a text note saying why, so the agent never executes it; the
stop reason is fixed up so the agent's loop stays valid. Streaming responses
are passed through as they arrive until the first tool-call event; from there
the rest of the stream is held until the calls can be judged.

On the way out, tool results in the request (what the agent got back from
running a tool) are scanned for planted instructions, the same check the
PostToolUse hooks do, and a warning is appended to a result that contains them.
The user's own messages are recorded as trusted intent.

Limits worth knowing: the proxy sees what the model *asked for*, not what the
agent finally ran (an agent that rewrites a command after the model is not
covered), and it cannot ask a human, so "ask" verdicts are blocked by default
(`--on-ask allow` lets them through as flags).
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterable, Iterator

from ..audit import AuditLog, home
from ..engine import Engine
from ..models import Decision, ToolCall, Verdict
from ..policy import load as load_policy
from ..state import FileStateStore
from .hooks_base import injection_warning
from .normalize import normalize

DEFAULT_UPSTREAMS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
}

_HOP = {"host", "content-length", "connection", "keep-alive", "transfer-encoding", "accept-encoding",
        "proxy-connection", "proxy-authorization", "te", "trailer", "upgrade"}

Judge = Callable[[str, Any, str], "Verdict | None"]   # (tool name, raw args, call id) -> verdict if blocked


def blocked_note(tool: str, verdict: Verdict) -> str:
    return (f"[Agent Guard blocked the tool call `{tool}`: {verdict.summary()}. "
            "The call was not run. Do not retry it in another form; explain to the user what you "
            "wanted to do and let them decide.]")


# --------------------------------------------------------------------------- #
# Guard: engine + per-session bookkeeping shared by all providers
# --------------------------------------------------------------------------- #


class Guard:
    def __init__(self, engine: Engine | None = None, on_ask: str = "block") -> None:
        self.engine = engine or Engine(load_policy(), FileStateStore(home() / "state"), AuditLog())
        self.on_ask = on_ask
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()

    def _first_time(self, session: str, key: str) -> bool:
        with self._lock:
            seen = self._seen.setdefault(session, set())
            if key in seen:
                return False
            if len(seen) > 5000:
                seen.clear()
            seen.add(key)
            return True

    def observe_user(self, session: str, text: str) -> None:
        if text and self._first_time(session, "u:" + _digest(text)):
            self.engine.observe_user(session, text)

    def observe_result(self, session: str, tool: str, call_id: str, text: str, agent: str) -> Verdict | None:
        """Scan one tool result. Returns the verdict if it contains planted instructions."""
        key = "r:" + (call_id or "") + _digest(text)
        if not self._first_time(session, key):
            return None
        canon, args = normalize(tool or "unknown", {})
        verdict = self.engine.observe(ToolCall(canon, args, session_id=session, agent=agent), text)
        return verdict if verdict.findings else None

    def judge(self, session: str, agent: str, tool: str, raw_args: Any, call_id: str = "") -> Verdict | None:
        canon, args = normalize(tool, raw_args)
        verdict = self.engine.evaluate(ToolCall(canon, args, session_id=session, agent=agent))
        if verdict.decision == Decision.BLOCK or (verdict.decision == Decision.ASK and self.on_ask == "block"):
            return verdict
        return None


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(_text(v.get("text", v) if isinstance(v, dict) else v) for v in value)
    if isinstance(value, dict) and "text" in value:
        return _text(value["text"])
    return json.dumps(value) if value is not None else ""


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #


@dataclass
class ResultRef:
    """A tool result found in a request, with a way to append a warning to it."""
    tool: str
    call_id: str
    text: str
    append: Callable[[str], None]


class Provider:
    name = "?"
    tool_events: set[str] = set()

    def match(self, path: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def users(self, body: dict[str, Any]) -> list[str]:
        return []

    def results(self, body: dict[str, Any]) -> list[ResultRef]:
        return []

    def session_seed(self, body: dict[str, Any]) -> str:
        users = self.users(body)
        return users[0] if users else ""

    def rewrite(self, body: dict[str, Any], judge: Judge) -> dict[str, Any]:  # pragma: no cover - abstract
        raise NotImplementedError

    def stream(self, events: Iterable[tuple[str | None, str]], judge: Judge) -> Iterator[tuple[str | None, str]]:
        """Default streaming: hold everything from the first tool event, then judge and replay."""
        raise NotImplementedError  # pragma: no cover


# -- OpenAI Chat Completions ---------------------------------------------------

class OpenAIChat(Provider):
    name = "openai-chat"

    def match(self, path: str) -> bool:
        return path.endswith("/chat/completions")

    def users(self, body):
        return [_text(m.get("content")) for m in body.get("messages") or [] if m.get("role") == "user"]

    def results(self, body):
        names: dict[str, str] = {}
        for m in body.get("messages") or []:
            for tc in m.get("tool_calls") or []:
                names[tc.get("id", "")] = (tc.get("function") or {}).get("name", "")
        out = []
        for m in body.get("messages") or []:
            if m.get("role") == "tool":
                def append(note: str, m: dict = m) -> None:
                    c = m.get("content")
                    m["content"] = (c + "\n\n" + note) if isinstance(c, str) else (c or []) + [{"type": "text", "text": note}]
                out.append(ResultRef(names.get(m.get("tool_call_id", ""), ""), m.get("tool_call_id", ""), _text(m.get("content")), append))
        return out

    def rewrite(self, body, judge):
        body = copy.deepcopy(body)
        for choice in body.get("choices") or []:
            msg = choice.get("message") or {}
            keep, notes = [], []
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function") or {}
                v = judge(fn.get("name", ""), fn.get("arguments"), tc.get("id", ""))
                if v:
                    notes.append(blocked_note(fn.get("name", ""), v))
                else:
                    keep.append(tc)
            if notes:
                msg["content"] = "\n".join(filter(None, [msg.get("content") or "", *notes]))
                if keep:
                    msg["tool_calls"] = keep
                else:
                    msg.pop("tool_calls", None)
                    if choice.get("finish_reason") == "tool_calls":
                        choice["finish_reason"] = "stop"
        return body

    def stream(self, events, judge):
        held: list[dict[str, Any]] = []
        calls: dict[int, dict[str, Any]] = {}
        holding = False
        for name, data in events:
            if data.strip() == "[DONE]":
                if holding:
                    yield from self._flush(held, calls, judge)
                    holding = False
                yield name, data
                continue
            try:
                chunk = json.loads(data)
            except ValueError:
                yield name, data
                continue
            choices = chunk.get("choices") or []
            delta = (choices[0].get("delta") or {}) if choices else {}
            if delta.get("tool_calls") or holding:
                holding = True
                held.append(chunk)
                for tc in delta.get("tool_calls") or []:
                    c = calls.setdefault(tc.get("index", 0), {"id": "", "name": "", "arguments": ""})
                    c["id"] = tc.get("id") or c["id"]
                    fn = tc.get("function") or {}
                    c["name"] += fn.get("name") or ""
                    c["arguments"] += fn.get("arguments") or ""
                continue
            yield name, data
        if holding:  # stream ended without [DONE]
            yield from self._flush(held, calls, judge)

    def _flush(self, held, calls, judge):
        verdicts = {i: judge(c["name"], c["arguments"], c["id"]) for i, c in calls.items()}
        blocked = {i for i, v in verdicts.items() if v}
        if not blocked:
            for chunk in held:
                yield None, json.dumps(chunk)
            return
        renum = {i: n for n, i in enumerate(sorted(set(calls) - blocked))}
        notes = "\n".join(blocked_note(calls[i]["name"], verdicts[i]) for i in sorted(blocked))
        base = {k: v for k, v in held[0].items() if k in ("id", "object", "created", "model")}
        note_chunk = {**base, "choices": [{"index": 0, "delta": {"content": notes}, "finish_reason": None}]}
        sent_note = False
        for chunk in held:
            choices = chunk.get("choices") or []
            if not choices:
                yield None, json.dumps(chunk)
                continue
            delta = choices[0].setdefault("delta", {})
            if delta.get("tool_calls"):
                kept = [{**tc, "index": renum[tc.get("index", 0)]} for tc in delta["tool_calls"]
                        if tc.get("index", 0) not in blocked]
                if kept:
                    delta["tool_calls"] = kept
                else:
                    delta.pop("tool_calls")
            finish = choices[0].get("finish_reason")
            if finish:
                if not sent_note:
                    yield None, json.dumps(note_chunk)
                    sent_note = True
                if finish == "tool_calls" and not renum:
                    choices[0]["finish_reason"] = "stop"
            if any(v for k, v in delta.items() if k != "role") or finish or chunk.get("usage"):
                yield None, json.dumps(chunk)
        if not sent_note:
            yield None, json.dumps(note_chunk)


# -- OpenAI Responses -------------------------------------------------------------

class OpenAIResponses(Provider):
    name = "openai-responses"
    _CALL_TYPES = {"function_call", "local_shell_call", "custom_tool_call"}

    def match(self, path: str) -> bool:
        return path.endswith("/responses")

    def _items(self, body):
        inp = body.get("input")
        return inp if isinstance(inp, list) else []

    def users(self, body):
        if isinstance(body.get("input"), str):
            return [body["input"]]
        return [_text(i.get("content")) for i in self._items(body) if i.get("role") == "user"]

    def results(self, body):
        names = {i.get("call_id", ""): i.get("name", "") for i in self._items(body) if i.get("type") in self._CALL_TYPES}
        out = []
        for item in self._items(body):
            if item.get("type") in ("function_call_output", "local_shell_call_output", "custom_tool_call_output"):
                def append(note: str, item: dict = item) -> None:
                    o = item.get("output")
                    item["output"] = (o + "\n\n" + note) if isinstance(o, str) else (o or []) + [{"type": "input_text", "text": note}]
                out.append(ResultRef(names.get(item.get("call_id", ""), ""), item.get("call_id", ""), _text(item.get("output")), append))
        return out

    def _judge_item(self, item, judge):
        t = item.get("type")
        if t == "function_call":
            return judge(item.get("name", ""), item.get("arguments"), item.get("call_id", ""))
        if t == "custom_tool_call":
            return judge(item.get("name", ""), {"input": item.get("input", "")}, item.get("call_id", ""))
        if t == "local_shell_call":
            return judge("local_shell", (item.get("action") or {}), item.get("call_id", ""))
        return None

    @staticmethod
    def _note_item(item, verdict):
        return {"type": "message", "id": f"msg_ag_{item.get('id', '')}", "role": "assistant", "status": "completed",
                "content": [{"type": "output_text", "text": blocked_note(item.get("name", item.get("type", "")), verdict),
                             "annotations": []}]}

    def rewrite(self, body, judge):
        body = copy.deepcopy(body)
        out = []
        for item in body.get("output") or []:
            v = self._judge_item(item, judge) if item.get("type") in self._CALL_TYPES else None
            out.append(self._note_item(item, v) if v else item)
        if "output" in body:
            body["output"] = out
        return body

    def stream(self, events, judge):
        # Tool-call items are only complete at response.output_item.done; hold
        # every event that belongs to a call item until then.
        call_idx: set[int] = set()
        held: dict[int, list[tuple[str | None, dict]]] = {}
        replaced: dict[int, dict] = {}
        for name, data in events:
            try:
                ev = json.loads(data)
            except ValueError:
                yield name, data
                continue
            typ = ev.get("type", name or "")
            idx = ev.get("output_index")
            item = ev.get("item") or {}
            if typ == "response.output_item.added" and item.get("type") in self._CALL_TYPES:
                call_idx.add(idx)
            if idx in call_idx:
                held.setdefault(idx, []).append((name, ev))
                if typ == "response.output_item.done":
                    v = self._judge_item(item, judge)
                    if v:
                        note = self._note_item(item, v)
                        replaced[idx] = note
                        yield "response.output_item.added", json.dumps({"type": "response.output_item.added", "output_index": idx, "item": {**note, "status": "in_progress", "content": []}})
                        yield "response.output_item.done", json.dumps({"type": "response.output_item.done", "output_index": idx, "item": note})
                    else:
                        for n, e in held[idx]:
                            yield n, json.dumps(e)
                    held.pop(idx, None)
                continue
            if typ in ("response.completed", "response.done", "response.incomplete") and replaced:
                resp = ev.get("response") or {}
                if isinstance(resp.get("output"), list):
                    resp["output"] = [replaced.get(i, it) for i, it in enumerate(resp["output"])]
                yield name, json.dumps(ev)
                continue
            yield name, data


# -- Anthropic Messages -----------------------------------------------------------

class Anthropic(Provider):
    name = "anthropic"

    def match(self, path: str) -> bool:
        return path.endswith("/messages") and "/chat/" not in path

    def users(self, body):
        out = []
        for m in body.get("messages") or []:
            if m.get("role") != "user":
                continue
            c = m.get("content")
            if isinstance(c, str):
                out.append(c)
            elif isinstance(c, list):
                texts = [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
                if texts:
                    out.append("\n".join(texts))
        return out

    def results(self, body):
        names: dict[str, str] = {}
        for m in body.get("messages") or []:
            if isinstance(m.get("content"), list):
                for b in m["content"]:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        names[b.get("id", "")] = b.get("name", "")
        out = []
        for m in body.get("messages") or []:
            if m.get("role") == "user" and isinstance(m.get("content"), list):
                for b in m["content"]:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        def append(note: str, b: dict = b) -> None:
                            c = b.get("content")
                            b["content"] = (c + "\n\n" + note) if isinstance(c, str) else (c or []) + [{"type": "text", "text": note}]
                        out.append(ResultRef(names.get(b.get("tool_use_id", ""), ""), b.get("tool_use_id", ""), _text(b.get("content")), append))
        return out

    def rewrite(self, body, judge):
        body = copy.deepcopy(body)
        content, any_blocked, any_kept = [], False, False
        for b in body.get("content") or []:
            if b.get("type") == "tool_use":
                v = judge(b.get("name", ""), b.get("input"), b.get("id", ""))
                if v:
                    any_blocked = True
                    content.append({"type": "text", "text": blocked_note(b.get("name", ""), v)})
                    continue
                any_kept = True
            content.append(b)
        if any_blocked:
            body["content"] = content
            if not any_kept and body.get("stop_reason") == "tool_use":
                body["stop_reason"] = "end_turn"
        return body

    def stream(self, events, judge):
        blocks: dict[int, dict[str, Any]] = {}
        held: dict[int, list[tuple[str | None, dict]]] = {}
        any_blocked = any_kept = False
        for name, data in events:
            try:
                ev = json.loads(data)
            except ValueError:
                yield name, data
                continue
            typ = ev.get("type", name or "")
            idx = ev.get("index")
            if typ == "content_block_start" and (ev.get("content_block") or {}).get("type") == "tool_use":
                cb = ev["content_block"]
                blocks[idx] = {"name": cb.get("name", ""), "id": cb.get("id", ""), "json": ""}
            if idx in blocks:
                held.setdefault(idx, []).append((name, ev))
                if typ == "content_block_delta":
                    blocks[idx]["json"] += (ev.get("delta") or {}).get("partial_json", "")
                if typ == "content_block_stop":
                    b = blocks.pop(idx)
                    v = judge(b["name"], b["json"] or "{}", b["id"])
                    if v:
                        any_blocked = True
                        yield "content_block_start", json.dumps({"type": "content_block_start", "index": idx, "content_block": {"type": "text", "text": ""}})
                        yield "content_block_delta", json.dumps({"type": "content_block_delta", "index": idx, "delta": {"type": "text_delta", "text": blocked_note(b["name"], v)}})
                        yield "content_block_stop", json.dumps({"type": "content_block_stop", "index": idx})
                    else:
                        any_kept = True
                        for n, e in held[idx]:
                            yield n, json.dumps(e)
                    held.pop(idx, None)
                continue
            if typ == "message_delta" and any_blocked and not any_kept:
                d = ev.get("delta") or {}
                if d.get("stop_reason") == "tool_use":
                    d["stop_reason"] = "end_turn"
                yield name, json.dumps(ev)
                continue
            yield name, data


# -- Gemini -----------------------------------------------------------------------

class Gemini(Provider):
    name = "gemini"

    def match(self, path: str) -> bool:
        return ":generateContent" in path or ":streamGenerateContent" in path

    def users(self, body):
        out = []
        for c in body.get("contents") or []:
            if c.get("role", "user") == "user":
                texts = [p.get("text", "") for p in c.get("parts") or [] if "text" in p]
                if texts:
                    out.append("\n".join(texts))
        return out

    def results(self, body):
        out = []
        for c in body.get("contents") or []:
            for p in c.get("parts") or []:
                fr = p.get("functionResponse")
                if isinstance(fr, dict):
                    def append(note: str, fr: dict = fr) -> None:
                        resp = fr.get("response")
                        if isinstance(resp, dict):
                            resp["agentguard_warning"] = note
                        else:
                            fr["response"] = {"output": resp, "agentguard_warning": note}
                    out.append(ResultRef(fr.get("name", ""), fr.get("id", ""), _text(fr.get("response")), append))
        return out

    def rewrite(self, body, judge):
        body = copy.deepcopy(body)
        for cand in body.get("candidates") or []:
            parts = (cand.get("content") or {}).get("parts")
            if not isinstance(parts, list):
                continue
            for i, p in enumerate(parts):
                fc = p.get("functionCall")
                if isinstance(fc, dict):
                    v = judge(fc.get("name", ""), fc.get("args"), fc.get("id", ""))
                    if v:
                        parts[i] = {"text": blocked_note(fc.get("name", ""), v)}
        return body

    def stream(self, events, judge):
        # Gemini streams whole parts per chunk, so each chunk can be judged on its own.
        for name, data in events:
            try:
                chunk = json.loads(data)
            except ValueError:
                yield name, data
                continue
            yield name, json.dumps(self.rewrite(chunk, judge)) if _has_fc(chunk) else data


def _has_fc(chunk: Any) -> bool:
    return '"functionCall"' in json.dumps(chunk)


PROVIDERS: list[Provider] = [OpenAIChat(), OpenAIResponses(), Anthropic(), Gemini()]


def provider_for(path: str) -> Provider | None:
    p = path.split("?")[0]
    for prov in PROVIDERS:
        if prov.match(p):
            return prov
    return None


def upstream_kind(path: str, headers: dict[str, str]) -> str:
    p = path.split("?")[0]
    if ":generateContent" in p or ":streamGenerateContent" in p or p.startswith("/v1beta") or "x-goog-api-key" in headers:
        return "gemini"
    if p.endswith("/messages") or "anthropic-version" in headers or "x-api-key" in headers:
        return "anthropic"
    return "openai"


# --------------------------------------------------------------------------- #
# Inspection applied to a request/response pair
# --------------------------------------------------------------------------- #


def inspect_request(guard: Guard, prov: Provider, body: dict[str, Any], session: str) -> dict[str, Any]:
    """Record user intent, scan tool results; return the (possibly annotated) body to forward."""
    for text in prov.users(body):
        guard.observe_user(session, text)
    for ref in prov.results(body):
        v = guard.observe_result(session, ref.tool, ref.call_id, ref.text, f"api:{prov.name}")
        if v:
            ref.append(injection_warning(v))
    return body


def session_id(prov: Provider, body: dict[str, Any], header: str | None) -> str:
    if header:
        return f"api:{header}"
    return f"api:{prov.name}:{_digest(prov.session_seed(body))}"


def parse_sse(lines: Iterable[bytes]) -> Iterator[tuple[str | None, str]]:
    name: str | None = None
    data: list[str] = []
    for raw in lines:
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data:
                yield name, "\n".join(data)
            name, data = None, []
            continue
        if line.startswith(":"):
            continue
        field_, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field_ == "event":
            name = value
        elif field_ == "data":
            data.append(value)
    if data:
        yield name, "\n".join(data)


def format_sse(name: str | None, data: str) -> bytes:
    return ((f"event: {name}\n" if name else "") + "".join(f"data: {d}\n" for d in data.split("\n")) + "\n").encode()


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #


@dataclass
class ProxyConfig:
    upstreams: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_UPSTREAMS))
    on_ask: str = "block"
    timeout: float = 600.0


def make_handler(guard: Guard, cfg: ProxyConfig) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def do_GET(self) -> None:
            self._forward(None)

        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            self._forward(self.rfile.read(n) if n else b"")

        def _forward(self, raw: bytes | None) -> None:
            headers = {k.lower(): v for k, v in self.headers.items()}
            kind = upstream_kind(self.path, headers)
            prov = provider_for(self.path) if raw else None
            body: dict[str, Any] | None = None
            session = ""
            if prov and raw:
                try:
                    body = json.loads(raw)
                except ValueError:
                    body = None
            if prov and isinstance(body, dict):
                session = session_id(prov, body, headers.get("x-agentguard-session"))
                body = inspect_request(guard, prov, body, session)
                raw = json.dumps(body).encode()

            url = cfg.upstreams[kind].rstrip("/") + self.path
            fwd = {k: v for k, v in self.headers.items() if k.lower() not in _HOP and k.lower() != "x-agentguard-session"}
            req = urllib.request.Request(url, data=raw, method=self.command, headers=fwd)
            try:
                resp = urllib.request.urlopen(req, timeout=cfg.timeout)
            except urllib.error.HTTPError as e:
                resp = e
            except Exception as e:  # upstream unreachable
                return self._send(502, {"Content-Type": "application/json"},
                                  json.dumps({"error": {"message": f"agentguard proxy: upstream error: {e}"}}).encode())

            status = resp.status if hasattr(resp, "status") else resp.code
            rheaders = {k: v for k, v in resp.headers.items() if k.lower() not in _HOP}
            ctype = resp.headers.get("Content-Type", "")
            agent = f"api:{prov.name}" if prov else "api"

            def judge(tool: str, args: Any, call_id: str) -> Verdict | None:
                return guard.judge(session, agent, tool, args, call_id)

            if prov is None or status >= 400 or not isinstance(body, dict):
                return self._send(status, rheaders, resp.read())
            if "text/event-stream" in ctype:
                return self._stream(status, rheaders, prov.stream(parse_sse(resp), judge))
            data = resp.read()
            try:
                out = json.dumps(prov.rewrite(json.loads(data), judge)).encode()
            except ValueError:
                out = data
            self._send(status, rheaders, out)

        def _send(self, status: int, headers: dict[str, str], data: bytes) -> None:
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _stream(self, status: int, headers: dict[str, str], events: Iterator[tuple[str | None, str]]) -> None:
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for name, data in events:
                    self.wfile.write(format_sse(name, data))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8787, cfg: ProxyConfig | None = None,
          guard: Guard | None = None) -> ThreadingHTTPServer:
    cfg = cfg or ProxyConfig()
    guard = guard or Guard(on_ask=cfg.on_ask)
    return ThreadingHTTPServer((host, port), make_handler(guard, cfg))
