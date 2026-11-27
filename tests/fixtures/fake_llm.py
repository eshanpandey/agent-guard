"""A scripted fake LLM server speaking the OpenAI (Responses and Chat Completions),
Anthropic Messages and Gemini generateContent wire formats.

On the first request of a conversation it answers with one tool call that a
rogue agent might make; once the request carries a tool result it answers
with plain text. Every request body is appended to a JSONL log so tests can
check what the agent sent back (for example, Agent Guard's deny reason).

    python fake_llm.py --port 0 --log /tmp/req.jsonl --command "rm -rf ~"

The chosen port is printed on stdout as `PORT <n>`. Used both to drive real
coding-agent CLIs (Codex, Gemini CLI) end to end and to test the API proxy.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ARGS: argparse.Namespace


def _pick(tools: list[str], prefs: list[str]) -> str:
    for p in prefs:
        if p in tools:
            return p
    return prefs[0]


def _tool_names_openai(body: dict[str, Any]) -> list[str]:
    out = []
    for t in body.get("tools") or []:
        if t.get("type") == "function":
            out.append(t.get("name") or (t.get("function") or {}).get("name"))
        elif t.get("type"):
            out.append(t["type"])
    return [n for n in out if n]


def _has_tool_result(body: dict[str, Any]) -> bool:
    s = json.dumps(body)
    return any(k in s for k in ('"function_call_output"', '"role": "tool"', '"tool_result"', '"functionResponse"'))


def _shell_args(tool: str) -> dict[str, Any]:
    if tool in ("shell", "local_shell"):
        return {"command": ["bash", "-lc", ARGS.command]}
    if tool == "exec_command":
        return {"cmd": ARGS.command}
    return {"command": ARGS.command}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a: Any) -> None:  # quiet
        pass

    def _body(self) -> dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        with open(ARGS.log, "a") as f:
            f.write(json.dumps({"path": self.path, "body": body}) + "\n")
        return body

    def _json(self, obj: Any, status: int = 200) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _sse(self, events: list[tuple[str | None, Any]]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        for name, data in events:
            chunk = (f"event: {name}\n" if name else "") + f"data: {data if isinstance(data, str) else json.dumps(data)}\n\n"
            self.wfile.write(chunk.encode())
            self.wfile.flush()
        self.close_connection = True

    def do_GET(self) -> None:  # model listings some clients probe
        if "models" in self.path:
            self._json({"object": "list", "data": [{"id": "fake-model", "object": "model"}],
                        "models": [{"name": "models/fake-model", "supportedGenerationMethods": ["generateContent"]}]})
        else:
            self._json({}, 404)

    def do_POST(self) -> None:
        body = self._body()
        path = self.path.split("?")[0]
        if path.endswith("/responses"):
            return self.openai_responses(body)
        if path.endswith("/chat/completions"):
            return self.openai_chat(body)
        if path.endswith("/messages"):
            return self.anthropic(body)
        if ":generateContent" in path or ":streamGenerateContent" in path:
            return self.gemini(body, stream=":streamGenerateContent" in path)
        if path.endswith(":countTokens"):
            return self._json({"totalTokens": 10})
        self._json({"error": "unknown path " + path}, 404)

    # -- OpenAI Responses ----------------------------------------------------
    def openai_responses(self, body: dict[str, Any]) -> None:
        tools = _tool_names_openai(body)
        done = _has_tool_result(body)
        usage = {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                 "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}
        if done:
            item = {"type": "message", "id": "msg_2", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": "Done.", "annotations": []}]}
        else:
            tool = _pick(tools, ["shell", "exec_command", "local_shell", "bash"]) if not ARGS.tool else ARGS.tool
            item = {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": tool,
                    "arguments": json.dumps(_shell_args(tool)), "status": "completed"}
        resp = {"id": "resp_1", "object": "response", "status": "completed", "model": body.get("model", "fake"),
                "output": [item], "usage": usage}
        if not body.get("stream"):
            return self._json(resp)
        self._sse([
            ("response.created", {"type": "response.created", "response": {**resp, "status": "in_progress", "output": []}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item}),
            ("response.completed", {"type": "response.completed", "response": resp}),
        ])

    # -- OpenAI Chat Completions --------------------------------------------
    def openai_chat(self, body: dict[str, Any]) -> None:
        tools = _tool_names_openai(body)
        done = _has_tool_result(body)
        tool = ARGS.tool or _pick(tools, ["shell", "bash", "run_shell_command", "exec_command"])
        if not tools and "Action Input" in json.dumps(body):
            # Text ReAct agents (CrewAI's default): tool calls are written as text.
            observed = "Observation:" in json.dumps(body["messages"][-1]) or len(body.get("messages", [])) > 2
            text = ("Thought: I now know the final answer\nFinal Answer: Done." if observed else
                    f"Thought: I should run a command.\nAction: {tool}\nAction Input: {json.dumps({'command': ARGS.command})}")
            msg = {"role": "assistant", "content": text}
            return self._json({"id": "chatcmpl-1", "object": "chat.completion", "model": body.get("model", "fake"),
                               "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
        if done:
            msg: dict[str, Any] = {"role": "assistant", "content": "Done."}
            finish = "stop"
        else:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": tool, "arguments": json.dumps(_shell_args(tool))}}]}
            finish = "tool_calls"
        if not body.get("stream"):
            return self._json({"id": "chatcmpl-1", "object": "chat.completion", "model": body.get("model", "fake"),
                               "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                               "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
        base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "model": body.get("model", "fake")}
        events: list[tuple[str | None, Any]] = []
        if done:
            events.append((None, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Done."}}]}))
        else:
            args = json.dumps(_shell_args(tool))
            half = len(args) // 2
            events.append((None, {**base, "choices": [{"index": 0, "delta": {"role": "assistant", "tool_calls": [
                {"index": 0, "id": "call_1", "type": "function", "function": {"name": tool, "arguments": args[:half]}}]}}]}))
            events.append((None, {**base, "choices": [{"index": 0, "delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": args[half:]}}]}}]}))
        events.append((None, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}))
        events.append((None, "[DONE]"))
        self._sse(events)

    # -- Anthropic Messages ---------------------------------------------------
    def anthropic(self, body: dict[str, Any]) -> None:
        tools = [t.get("name") for t in body.get("tools") or []]
        done = _has_tool_result(body)
        tool = ARGS.tool or _pick(tools, ["Bash", "bash"])
        if done:
            content: list[dict[str, Any]] = [{"type": "text", "text": "Done."}]
            stop = "end_turn"
        else:
            content = [{"type": "text", "text": "Cleaning up."},
                       {"type": "tool_use", "id": "toolu_1", "name": tool, "input": {"command": ARGS.command}}]
            stop = "tool_use"
        msg = {"id": "msg_1", "type": "message", "role": "assistant", "model": body.get("model", "fake"),
               "content": content, "stop_reason": stop, "stop_sequence": None,
               "usage": {"input_tokens": 10, "output_tokens": 5}}
        if not body.get("stream"):
            return self._json(msg)
        events: list[tuple[str | None, Any]] = [
            ("message_start", {"type": "message_start", "message": {**msg, "content": [], "stop_reason": None}})]
        for i, block in enumerate(content):
            if block["type"] == "text":
                events.append(("content_block_start", {"type": "content_block_start", "index": i,
                                                       "content_block": {"type": "text", "text": ""}}))
                events.append(("content_block_delta", {"type": "content_block_delta", "index": i,
                                                       "delta": {"type": "text_delta", "text": block["text"]}}))
            else:
                args = json.dumps(block["input"])
                events.append(("content_block_start", {"type": "content_block_start", "index": i, "content_block":
                                                       {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}}))
                for part in (args[: len(args) // 2], args[len(args) // 2:]):
                    events.append(("content_block_delta", {"type": "content_block_delta", "index": i,
                                                           "delta": {"type": "input_json_delta", "partial_json": part}}))
            events.append(("content_block_stop", {"type": "content_block_stop", "index": i}))
        events.append(("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                         "usage": {"output_tokens": 5}}))
        events.append(("message_stop", {"type": "message_stop"}))
        self._sse(events)

    # -- Gemini -----------------------------------------------------------------
    def gemini(self, body: dict[str, Any], stream: bool) -> None:
        tools = [f.get("name") for t in body.get("tools") or [] for f in t.get("functionDeclarations") or []]
        done = _has_tool_result(body)
        tool = ARGS.tool or _pick(tools, ["run_shell_command", "shell"])
        if done:
            parts: list[dict[str, Any]] = [{"text": "Done."}]
        else:
            parts = [{"functionCall": {"name": tool, "args": {"command": ARGS.command}}}]
        resp = {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP", "index": 0}],
                "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15},
                "modelVersion": "fake-model"}
        if not stream:
            return self._json(resp)
        self._sse([(None, resp)])


def main() -> None:
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--log", required=True)
    p.add_argument("--command", default="rm -rf ~")
    p.add_argument("--tool", default=None, help="Force this tool name instead of picking from the request.")
    ARGS = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    print(f"PORT {srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
