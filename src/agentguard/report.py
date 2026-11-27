"""Summaries of the audit log, grouped by OWASP Agentic Top 10 category."""

from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

OWASP_AGENTIC = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

RULES = {
    "permission_bypass": "AI agent launched with approvals disabled",
    "destructive_command": "Deletes data, infrastructure or history",
    "credential_access": "Reads keys, tokens or secrets files",
    "exfiltration": "Sends data or secrets to unapproved destinations",
    "supply_chain": "Runs downloaded or obfuscated code, installs unvetted packages",
    "unsafe_deserialization": "Loads pickle-style formats that can execute code",
    "unpinned_model": "Downloads a model without pinning a revision",
    "production_change": "Writes to production or during a code freeze",
    "acts_on_behalf": "Moves money, creates accounts or posts as the user",
    "scope_violation": "Writes outside the workspace or to startup files",
    "tainted_action": "Risky action after reading untrusted or injected content",
    "runaway_agent": "Loops, floods and rate-limit breaches",
    "prompt_injection": "Tool output carries instructions aimed at the agent",
}


def build(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    decisions: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    owasp: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    sessions: set[str] = set()
    critical: list[dict[str, Any]] = []
    total = 0
    for rec in records:
        total += 1
        sessions.add(rec.get("session", "?"))
        decisions[rec.get("decision", "?")] += 1
        for f in rec.get("findings", []):
            severities[f["severity"]] += 1
            rules[f["rule_id"]] += 1
            for o in f.get("owasp", []):
                owasp[o] += 1
            if f["severity"] == "critical":
                critical.append({"ts": rec.get("ts"), "tool": rec.get("tool"), "message": f["message"], "decision": rec.get("decision")})
    return {
        "events": total,
        "sessions": len(sessions),
        "decisions": dict(decisions),
        "severities": dict(severities),
        "owasp": dict(sorted(owasp.items())),
        "rules": dict(rules.most_common()),
        "critical": critical[-20:],
    }


def render(summary: dict[str, Any], fmt: str = "text") -> str:
    md = fmt == "md"
    lines: list[str] = []
    h = (lambda s: f"## {s}") if md else (lambda s: f"\n{s}\n" + "-" * len(s))
    lines.append("# Agent Guard report" if md else "AGENT GUARD REPORT")
    d = summary["decisions"]
    lines.append(f"\n{summary['events']} events across {summary['sessions']} sessions: "
                 f"{d.get('block', 0)} blocked, {d.get('ask', 0)} sent to a human, {d.get('flag', 0)} flagged, {d.get('allow', 0)} allowed.")
    lines.append(h("By OWASP Agentic Top 10"))
    if md:
        lines += ["", "| ID | Risk | Findings |", "| --- | --- | --- |"]
    for k, v in summary["owasp"].items():
        lines.append(f"| {k} | {OWASP_AGENTIC.get(k, '')} | {v} |" if md else f"  {k}  {OWASP_AGENTIC.get(k, ''):<40} {v:>5}")
    lines.append(h("By rule"))
    for k, v in summary["rules"].items():
        lines.append(f"- **{k}** ({v}): {RULES.get(k, '')}" if md else f"  {k:<24} {v:>5}  {RULES.get(k, '')}")
    if summary["critical"]:
        lines.append(h("Recent critical findings"))
        for c in summary["critical"]:
            lines.append(f"- {c['ts']} `{c['tool']}` {c['decision']}: {c['message']}" if md else f"  {c['ts']}  {c['tool']:<14} {c['decision']:<6} {c['message']}")
    return "\n".join(lines) + "\n"
