#!/usr/bin/env python3
"""Standard-library-only Agent Guard CLI used by the plugin's slash commands.

The full CLI (`pip install agentguard`, then `agentguard ...`) has more
commands; this one covers what the slash commands need without extra installs.
"""

import argparse
import json
import os
import sys

ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from agentguard import __version__  # noqa: E402
from agentguard.audit import AuditLog, home  # noqa: E402
from agentguard.engine import Engine  # noqa: E402
from agentguard.models import ToolCall  # noqa: E402
from agentguard.policy import load as load_policy  # noqa: E402
from agentguard.report import build, render  # noqa: E402


def cmd_report(args):
    log = AuditLog()
    if not log.path.exists():
        print(f"No audit log yet at {log.path}. Agent Guard writes one as soon as Claude makes a tool call.")
        return 0
    print(render(build(log.records()), args.format), end="")
    return 0


def cmd_verify(args):
    log = AuditLog()
    if not log.path.exists():
        print(f"No audit log yet at {log.path}.")
        return 0
    ok, _, msg = log.verify()
    print(f"{'OK' if ok else 'TAMPERED'}: {msg} ({log.path})")
    return 0 if ok else 1


def cmd_tail(args):
    log = AuditLog()
    rows = [r for r in log.records() if args.all or r.get("max_severity")] if log.path.exists() else []
    if not rows:
        print("No flagged events yet." if not args.all else "No events yet.")
        return 0
    for r in rows[-args.count:]:
        top = r.get("findings") or [{}]
        print(f"{r.get('ts')}  {r.get('decision', '?'):<5}  {r.get('tool', '?'):<14}  {top[0].get('message', '')}")
    return 0


def cmd_status(args):
    policy = load_policy(search_from=args.cwd or os.getcwd())
    try:
        import yaml  # noqa: F401
        yaml_note = "PyYAML installed: full policy syntax"
    except ImportError:
        yaml_note = "PyYAML not installed: simple policies only (custom_rules need `pip install pyyaml`)"
    log = AuditLog()
    print(f"Agent Guard {__version__}  (Python {sys.version.split()[0]})")
    print(f"Mode: {policy.mode}   change freeze: {policy.change_freeze}")
    print(f"Disabled rules: {', '.join(sorted(policy.disabled_rules)) or 'none'}   custom rules: {len(policy.custom_rules)}")
    print(f"Audit log: {log.path}{'' if log.path.exists() else ' (not created yet)'}")
    print(f"State: {home() / 'state'}")
    print(yaml_note)
    return 0


def cmd_check(args):
    try:
        tool_args = json.loads(args.args) if args.args.strip().startswith("{") else {"command": args.args}
    except json.JSONDecodeError as exc:
        print(f"Arguments are not valid JSON: {exc}")
        return 2
    engine = Engine(load_policy(search_from=os.getcwd()))
    verdict = engine.evaluate(ToolCall(tool=args.tool, args=tool_args, session_id="plugin-check", cwd=os.getcwd()))
    print(verdict.decision.upper())
    for f in verdict.findings:
        print(f"  [{f.severity}] {f.rule_id}: {f.message}  ({', '.join(f.owasp + f.atlas)})")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="agentguard-lite")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("report")
    r.add_argument("--format", choices=["text", "md"], default="md")
    r.set_defaults(fn=cmd_report)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    t = sub.add_parser("tail")
    t.add_argument("count", nargs="?", type=int, default=20)
    t.add_argument("--all", action="store_true")
    t.set_defaults(fn=cmd_tail)
    s = sub.add_parser("status")
    s.add_argument("--cwd")
    s.set_defaults(fn=cmd_status)
    c = sub.add_parser("check")
    c.add_argument("tool")
    c.add_argument("args", help='a shell command, or the tool input as JSON')
    c.set_defaults(fn=cmd_check)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
