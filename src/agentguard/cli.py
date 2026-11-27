"""Command-line interface: `agentguard --help`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import __version__
from .audit import AuditLog, home
from .engine import Engine
from .models import Decision, Severity, ToolCall
from .policy import default_policy_text, load as load_policy
from .report import OWASP_AGENTIC, RULES, build, render

_COLORS = {"allow": "green", "flag": "yellow", "ask": "magenta", "block": "red"}
_SEV_COLORS = {"info": "white", "low": "cyan", "medium": "yellow", "high": "magenta", "critical": "red"}


@click.group()
@click.version_option(__version__, prog_name="agentguard")
def main() -> None:
    """Agent Guard: detect and stop rogue AI agent behaviour."""


@main.command()
@click.argument("tool")
@click.option("--args", "args_json", default="{}", help='Tool arguments as JSON, e.g. \'{"command": "rm -rf ~"}\'.')
@click.option("--command", "-c", help="Shortcut for a shell tool's command argument.")
@click.option("--policy", type=click.Path(exists=True), help="Policy file to use.")
@click.option("--json", "as_json", is_flag=True, help="Print the verdict as JSON.")
def check(tool: str, args_json: str, command: str | None, policy: str | None, as_json: bool) -> None:
    """Evaluate a single tool call and print the verdict."""
    args = json.loads(args_json)
    if command:
        args["command"] = command
    verdict = Engine(load_policy(policy)).evaluate(ToolCall(tool=tool, args=args, agent="cli", cwd=str(Path.cwd())))
    if as_json:
        click.echo(json.dumps(verdict.to_dict(), indent=2))
    else:
        click.secho(verdict.decision.upper(), fg=_COLORS[verdict.decision], bold=True)
        for f in verdict.findings:
            click.echo(f"  [{click.style(str(f.severity), fg=_SEV_COLORS[str(f.severity)])}] {f.rule_id}: {f.message}  "
                       f"({', '.join(f.owasp + f.atlas)})")
    sys.exit(2 if verdict.decision == Decision.BLOCK else 0)


@main.group()
def hook() -> None:
    """Hook entry points called by agent frameworks."""


@hook.command("claude-code")
def hook_claude_code() -> None:
    """Handle a Claude Code PreToolUse/PostToolUse hook event from stdin."""
    from .integrations.claude_code import run_hook
    sys.exit(run_hook())


@hook.command("cursor")
def hook_cursor() -> None:
    """Handle a Cursor hook event from stdin."""
    from .integrations.registry import get
    sys.exit(get("cursor").run())


@hook.command("codex")
def hook_codex() -> None:
    """Handle an OpenAI Codex CLI hook event from stdin."""
    from .integrations.registry import get
    sys.exit(get("codex").run())


@hook.command("gemini")
def hook_gemini() -> None:
    """Handle a Gemini CLI hook event from stdin."""
    from .integrations.registry import get
    sys.exit(get("gemini").run())


@hook.command("copilot")
def hook_copilot() -> None:
    """Handle a GitHub Copilot (CLI or cloud agent) hook event from stdin."""
    from .integrations.registry import get
    sys.exit(get("copilot").run())


@main.group()
def install() -> None:
    """Install Agent Guard into an agent."""


@install.command("claude-code")
@click.option("--user", is_flag=True, help="Install for every project (~/.claude/settings.json).")
def install_claude_code(user: bool) -> None:
    """Add Agent Guard hooks to Claude Code settings."""
    from .integrations.claude_code import install as do_install
    target = Path.home() / ".claude" / "settings.json" if user else Path.cwd() / ".claude" / "settings.json"
    path = do_install(target)
    click.echo(f"Agent Guard hooks added to {path}. Restart Claude Code to load them.")


def _install_hooks(name: str, label: str, user: bool) -> None:
    from .integrations.registry import get
    adapter = get(name)
    path = adapter.install(adapter.settings_path(user, Path.cwd()))
    click.echo(f"Agent Guard hooks added to {path}. Restart {label} to load them.")
    if adapter.post_install_note:
        click.echo(adapter.post_install_note)


_USER_HELP = "Install for every project (in your home folder) instead of this one."


@install.command("cursor")
@click.option("--user", is_flag=True, help=_USER_HELP)
def install_cursor(user: bool) -> None:
    """Add Agent Guard hooks to Cursor (.cursor/hooks.json)."""
    _install_hooks("cursor", "Cursor", user)


@install.command("codex")
@click.option("--user", is_flag=True, help=_USER_HELP)
def install_codex(user: bool) -> None:
    """Add Agent Guard hooks to OpenAI Codex CLI (.codex/hooks.json)."""
    _install_hooks("codex", "Codex", user)


@install.command("gemini")
@click.option("--user", is_flag=True, help=_USER_HELP)
def install_gemini(user: bool) -> None:
    """Add Agent Guard hooks to Gemini CLI (.gemini/settings.json)."""
    _install_hooks("gemini", "Gemini CLI", user)


@install.command("copilot")
@click.option("--user", is_flag=True, help=_USER_HELP)
def install_copilot(user: bool) -> None:
    """Add Agent Guard hooks to GitHub Copilot CLI / cloud agent (.github/hooks/agentguard.json)."""
    _install_hooks("copilot", "Copilot", user)


@main.command(context_settings={"ignore_unknown_options": True})
@click.option("--name", help="Label for this server in the audit log.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def proxy(name: str | None, command: tuple[str, ...]) -> None:
    """Run an MCP server behind Agent Guard: agentguard proxy -- <server command>."""
    from .integrations.mcp_proxy import run_proxy
    sys.exit(run_proxy(list(command), name=name))


@main.command("api-proxy")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8787, show_default=True, type=int)
@click.option("--openai-upstream", default="https://api.openai.com", show_default=True, help="Where OpenAI-format requests go (any OpenAI-compatible server).")
@click.option("--anthropic-upstream", default="https://api.anthropic.com", show_default=True)
@click.option("--gemini-upstream", default="https://generativelanguage.googleapis.com", show_default=True)
@click.option("--on-ask", type=click.Choice(["block", "allow"]), default="block", show_default=True,
              help="The proxy cannot ask a human: block calls the policy would ask about, or let them through as flags.")
def api_proxy(host: str, port: int, openai_upstream: str, anthropic_upstream: str, gemini_upstream: str, on_ask: str) -> None:
    """Guard any agent at the model API: check every tool call the model asks for.

    Point the agent at the proxy, e.g. OPENAI_BASE_URL=http://127.0.0.1:8787/v1,
    ANTHROPIC_BASE_URL=http://127.0.0.1:8787 or GOOGLE_GEMINI_BASE_URL=http://127.0.0.1:8787.
    """
    from .integrations.api_proxy import ProxyConfig, serve
    cfg = ProxyConfig(upstreams={"openai": openai_upstream, "anthropic": anthropic_upstream, "gemini": gemini_upstream},
                      on_ask=on_ask)
    srv = serve(host, port, cfg)
    h, p = srv.server_address[:2]
    click.echo(f"Agent Guard API proxy on http://{h}:{p}")
    click.echo(f"  OpenAI:    OPENAI_BASE_URL=http://{h}:{p}/v1")
    click.echo(f"  Anthropic: ANTHROPIC_BASE_URL=http://{h}:{p}")
    click.echo(f"  Gemini:    GOOGLE_GEMINI_BASE_URL=http://{h}:{p}", err=False)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show every finding.")
@click.option("--json", "as_json", is_flag=True)
def replay(paths: tuple[str, ...], verbose: bool, as_json: bool) -> None:
    """Replay real incidents (and normal sessions) and score detection."""
    from .replay import run_all, summarize
    results = run_all(list(paths) or None)
    s = summarize(results)
    if as_json:
        click.echo(json.dumps({"summary": s, "results": [
            {"id": r.id, "kind": r.kind, "passed": r.passed, "max_severity": str(r.max_severity) if r.max_severity is not None else None,
             "rules": r.fired_rules, "missing": r.missing_rules, "first_alert_step": r.first_alert_step} for r in results]}, indent=2))
        sys.exit(0 if s["detected"] == s["attacks"] and s["false_positives"] == 0 else 1)
    for r in results:
        mark = click.style("PASS", fg="green") if r.passed else click.style("FAIL", fg="red")
        sev = str(r.max_severity) if r.max_severity is not None else "none"
        click.echo(f"{mark}  {r.kind:<6}  {r.id:<26} max={sev:<8} want {r.expected:<12} {r.title}")
        if r.missing_rules:
            click.echo(f"        missing rules: {', '.join(r.missing_rules)}")
        if verbose:
            for f in r.findings:
                click.echo(f"        [{f.severity}] {f.rule_id}: {f.message}")
    click.echo(f"\nDetected {s['detected']}/{s['attacks']} incidents; "
               f"{s['false_positives']}/{s['benign']} normal sessions wrongly flagged.")
    sys.exit(0 if s["detected"] == s["attacks"] and s["false_positives"] == 0 else 1)


@main.group()
def log() -> None:
    """Inspect the tamper-evident audit log."""


@log.command("verify")
@click.option("--path", type=click.Path(), help="Log file (default ~/.agentguard/audit.jsonl).")
def log_verify(path: str | None) -> None:
    """Check that no record was edited, removed or reordered."""
    ok, n, msg = AuditLog(path).verify()
    click.secho(("OK: " if ok else "TAMPERED: ") + msg, fg="green" if ok else "red")
    sys.exit(0 if ok else 1)


@log.command("tail")
@click.option("-n", default=20, help="Number of records.")
@click.option("--path", type=click.Path())
@click.option("--min-severity", default="low", help="Hide records below this severity.")
def log_tail(n: int, path: str | None, min_severity: str) -> None:
    """Show the most recent flagged events."""
    floor = Severity.parse(min_severity)
    recs = [r for r in AuditLog(path).records() if r.get("max_severity") and Severity.parse(r["max_severity"]) >= floor]
    for r in recs[-n:]:
        click.echo(f"{r['ts']}  {click.style(r['decision'].upper(), fg=_COLORS.get(r['decision'], 'white')):<15} "
                   f"{r['tool']:<16} {r['findings'][0]['message']}")


@main.command()
@click.option("--path", type=click.Path(), help="Log file (default ~/.agentguard/audit.jsonl).")
@click.option("--format", "fmt", type=click.Choice(["text", "md", "json"]), default="text")
def report(path: str | None, fmt: str) -> None:
    """Summarise the audit log by OWASP Agentic Top 10 category."""
    summary = build(AuditLog(path).records())
    click.echo(json.dumps(summary, indent=2) if fmt == "json" else render(summary, fmt))


@main.command()
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init(force: bool) -> None:
    """Write a starter .agentguard.yaml policy in this folder."""
    target = Path.cwd() / ".agentguard.yaml"
    if target.exists() and not force:
        raise click.ClickException(f"{target} exists; use --force to overwrite")
    target.write_text(default_policy_text())
    click.echo(f"Wrote {target}")


@main.command()
def rules() -> None:
    """List the built-in detection rules and the OWASP categories."""
    click.echo("Rules:")
    for k, v in RULES.items():
        click.echo(f"  {k:<24} {v}")
    click.echo("\nOWASP Top 10 for Agentic Applications (2026):")
    for k, v in OWASP_AGENTIC.items():
        click.echo(f"  {k}  {v}")
    click.echo(f"\nAudit log and state live in {home()}")


if __name__ == "__main__":  # pragma: no cover
    main()
