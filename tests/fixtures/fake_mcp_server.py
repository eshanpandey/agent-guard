"""Minimal MCP-like stdio server for tests: echoes tool calls back."""
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "tools/call":
        args = msg["params"].get("arguments", {})
        text = args.get("reply", f"ran {msg['params']['name']}")
        out = {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}]}}
    else:
        out = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"ok": True}}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
