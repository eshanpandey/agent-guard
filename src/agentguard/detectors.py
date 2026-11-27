"""Detectors: small functions that each look for one kind of rogue behaviour.

Every detector takes a `Context` and returns a list of `Finding`s. Detectors are
deliberately transparent (regexes and simple state) so each finding can be
explained in one sentence and mapped to the OWASP Top 10 for Agentic
Applications (ASI01-ASI10) and MITRE ATLAS.
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from . import provenance as pv
from .models import Finding, Severity, ToolCall
from .policy import Policy
from .state import SessionState

# --------------------------------------------------------------------------- #
# Tool classification
# --------------------------------------------------------------------------- #

_SHELL = re.compile(r"(?i)(^|_|\b)(bash|shell|sh|zsh|terminal|exec|execute|run_command|run_terminal_cmd|command|powershell|cmd)(\b|_|$)")
_FILE_WRITE = re.compile(r"(?i)(^|_|\b)(write|edit|multiedit|create_file|save_file|str_replace|apply_patch|notebookedit|delete_file|move_file)(\b|_|$)")
_FILE_READ = re.compile(r"(?i)(^|_|\b)(read|read_file|view|cat|open_file|get_file)(\b|_|$)")
_WEB = re.compile(r"(?i)(fetch|browse|browser|navigate|web|http|url|scrape|crawl|search)")
_EMAIL = re.compile(r"(?i)(mail|email|smtp)")
_MESSAGE = re.compile(r"(?i)(send_message|send_sms|sms|imessage|whatsapp|slack|telegram|discord|chat_post|post_message|send_dm|notify)")
_UNTRUSTED_SOURCES = re.compile(r"(?i)(fetch|browse|browser|navigate|web|http|scrape|crawl|search|mail|email|inbox|read_message|get_message|issue|comment|skill|readme|download)")
_SEND = re.compile(r"(?i)(send|post|reply|forward|publish|submit|create_message|draft)")


def is_shell(call: ToolCall) -> bool:
    return bool(_SHELL.search(call.tool)) or any(k in call.args for k in ("command", "cmd", "script"))


def is_file_write(call: ToolCall) -> bool:
    return bool(_FILE_WRITE.search(call.tool))


def is_file_read(call: ToolCall) -> bool:
    return bool(_FILE_READ.search(call.tool)) and not is_file_write(call)


def is_email_send(call: ToolCall) -> bool:
    return bool(_EMAIL.search(call.tool)) and (bool(_SEND.search(call.tool)) or any(k in call.args for k in ("to", "bcc", "cc", "recipients")))


def is_message_send(call: ToolCall) -> bool:
    return is_email_send(call) or (bool(_MESSAGE.search(call.tool)) and not _FILE_READ.search(call.tool))


def is_sink(call: ToolCall) -> bool:
    """A tool that changes something: send, delete, transfer, grant, reserve...

    Declared metadata wins (MCP tool annotations); otherwise the tool's name decides.
    """
    hints = (call.meta or {}).get("annotations") or call.meta or {}
    if hints.get("destructiveHint") is True or hints.get("readOnlyHint") is False:
        return True
    if hints.get("readOnlyHint") is True:
        return False
    words = {_stem(w) for w in pv.tokens(pv.split_identifier(call.tool))}
    return bool(words & _SINK_WORDS)


def _stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


_SINK_WORDS = {_stem(w) for w in pv.ACTION_WORDS} - {"download", "copy"}


def is_untrusted_source(tool: str) -> bool:
    return bool(_UNTRUSTED_SOURCES.search(tool))


def command_text(call: ToolCall) -> str:
    for key in ("command", "cmd", "script", "code", "input"):
        v = call.args.get(key)
        if isinstance(v, str):
            return v
    return call.text()


def written_content(call: ToolCall) -> str:
    parts = []
    for key in ("content", "new_string", "new_str", "text", "patch", "file_text", "edits"):
        v = call.args.get(key)
        if v is not None:
            parts.append(v if isinstance(v, str) else str(v))
    return "\n".join(parts)


def target_path(call: ToolCall) -> str | None:
    for key in ("file_path", "path", "filename", "target", "notebook_path"):
        v = call.args.get(key)
        if isinstance(v, str):
            return v
    return None


# --------------------------------------------------------------------------- #
# Context passed to detectors
# --------------------------------------------------------------------------- #


@dataclass
class Context:
    call: ToolCall
    policy: Policy
    state: SessionState

    @property
    def workspace(self) -> str:
        return os.path.realpath(os.path.expanduser(self.policy.workspace or self.call.cwd or os.getcwd()))

    def outside_workspace(self, path: str) -> bool:
        p = os.path.expanduser(path)
        if not os.path.isabs(p):
            p = os.path.join(self.call.cwd or self.workspace, p)
        p = os.path.realpath(p)
        ws = self.workspace
        return not (p == ws or p.startswith(ws.rstrip(os.sep) + os.sep))


Detector = Callable[[Context], list[Finding]]
REGISTRY: dict[str, Detector] = {}


def detector(rule_id: str) -> Callable[[Detector], Detector]:
    def wrap(fn: Detector) -> Detector:
        REGISTRY[rule_id] = fn
        fn.rule_id = rule_id  # type: ignore[attr-defined]
        return fn
    return wrap


def _f(rule_id: str, sev: Severity, msg: str, owasp: list[str], atlas: list[str] | None = None, evidence: str = "") -> Finding:
    return Finding(rule_id, sev, msg, owasp, atlas or [], evidence[:300])


def _first(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(0) if m else None


# --------------------------------------------------------------------------- #
# 1. Permission bypass: agents run with every approval switched off
#    (Amazon Q wiper, Nx "s1ngularity")
# --------------------------------------------------------------------------- #

_BYPASS = re.compile(
    r"--dangerously-skip-permissions|--trust-all-tools|--dangerously-bypass-approvals-and-sandbox"
    r"|--yolo\b|--approval-mode[= ]yolo|--allow-all-tools|--full-auto|--permission-mode[= ]bypassPermissions"
)


@detector("permission_bypass")
def permission_bypass(ctx: Context) -> list[Finding]:
    text = command_text(ctx.call) if is_shell(ctx.call) else ctx.call.text()
    hit = _first(_BYPASS, text)
    if not hit:
        return []
    return [_f("permission_bypass", Severity.CRITICAL,
               f"Launches an AI agent with its safety approvals disabled ({hit})",
               ["ASI02", "ASI03"], ["AML.T0053"], hit)]


# --------------------------------------------------------------------------- #
# 2. Destructive commands (Replit database wipe, Amazon Q wiper, OpenClaw deletions)
# --------------------------------------------------------------------------- #

_DANGEROUS_RM_TARGETS = re.compile(r"""^["']?(/|/\*|~|~/|~/\*|\$HOME|\$\{HOME\}|\$HOME/\*|\*|\.|\./\*|\.\.|\.\./.*|/(home|etc|usr|var|bin|boot|lib|opt|root|System|Users)(/.*)?|[A-Za-z]:\\.*)["']?/?$""")
_SQL_DROP = re.compile(r"(?i)\b(drop\s+(table|database|schema|collection)|truncate\s+(table\s+)?\w+|db\.dropDatabase\(|\.drop\(\))")
_SQL_DELETE_ALL = re.compile(r"(?i)\bdelete\s+from\s+[\w.\"`]+\s*(;|$|\"|'|\))")
_CRITICAL_CMDS = re.compile(r"(\bmkfs(\.\w+)?\b|\bdd\s+[^|;]*of=/dev/(sd|nvme|disk|hd)|:\(\)\s*\{\s*:\|:&\s*\};:|\bchmod\s+-R\s+0?777\s+/(\s|$)|\bformat\s+[a-zA-Z]:)")
_POWER = re.compile(r"(^|[;&|]\s*|sudo\s+)(shutdown|reboot|halt|poweroff)\b")
_HIGH_CMDS = [
    (re.compile(r"\bgit\s+push\b[^;&|]*(\s--force\b|\s-f\b|\s--force-with-lease\b)"), "Force-pushes git history"),
    (re.compile(r"\b(terraform|pulumi|cdk)\s+destroy\b"), "Destroys infrastructure"),
    (re.compile(r"\bkubectl\s+delete\s+(ns|namespace|all|deployment|pvc|--all)\b"), "Deletes Kubernetes resources"),
    (re.compile(r"\baws\s+s3\s+rb\b|\baws\s+s3\s+rm\b[^;&|]*--recursive|\baws\s+\S+\s+(delete-\S+|terminate-instances)"), "Deletes AWS resources"),
    (re.compile(r"\bgcloud\s+[^;&|]*\bdelete\b|\baz\s+[^;&|]*\bdelete\b"), "Deletes cloud resources"),
    (re.compile(r"\bfind\s+(/|~|\$HOME)\S*\s[^;&|]*-delete\b"), "Bulk-deletes files across the system"),
    (re.compile(r"\b(dropdb|redis-cli\s+[^;&|]*flushall|mongo\S*\s[^;&|]*dropDatabase)\b", re.I), "Wipes a database"),
]
_MEDIUM_CMDS = [
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "Discards uncommitted git work"),
    (re.compile(r"\bgit\s+clean\s+-[a-z]*f[a-z]*d|\bgit\s+clean\s+-[a-z]*d[a-z]*f"), "Deletes untracked files"),
]
_DESTRUCTIVE_TOOL = re.compile(r"(?i)(^|_|\b)(delete|remove|drop|destroy|purge|trash|wipe|truncate|erase|terminate)")


def _rm_targets(cmd: str) -> list[str]:
    targets: list[str] = []
    for segment in re.split(r"[;&|\n]+", cmd):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        for i, tok in enumerate(tokens):
            if os.path.basename(tok) != "rm":
                continue
            flags = [t for t in tokens[i + 1:] if t.startswith("-")]
            recursive = any(("r" in f.lstrip("-").lower() and not f.startswith("--")) or f in ("--recursive",) for f in flags)
            if not recursive:
                continue
            targets.extend(t for t in tokens[i + 1:] if not t.startswith("-"))
    return targets


@detector("destructive_command")
def destructive_command(ctx: Context) -> list[Finding]:
    call = ctx.call
    out: list[Finding] = []
    owasp, atlas = ["ASI02", "ASI10"], ["AML.T0048"]

    if is_shell(call) or call.tool.lower() in ("sql", "query", "execute_sql", "run_sql", "db_query"):
        cmd = command_text(call)
        for t in _rm_targets(cmd):
            expanded = t.replace("$HOME", "~").replace("${HOME}", "~")
            if _DANGEROUS_RM_TARGETS.match(t):
                out.append(_f("destructive_command", Severity.CRITICAL, f"Recursively deletes a system, home or wildcard path ({t})", owasp, atlas, cmd))
            elif os.path.isabs(os.path.expanduser(expanded)) and ctx.outside_workspace(expanded):
                out.append(_f("destructive_command", Severity.HIGH, f"Recursively deletes a path outside the workspace ({t})", owasp, atlas, cmd))
        if hit := _first(_CRITICAL_CMDS, cmd):
            out.append(_f("destructive_command", Severity.CRITICAL, f"Runs a disk- or system-destroying command ({hit})", owasp, atlas, cmd))
        if hit := _first(_POWER, cmd):
            out.append(_f("destructive_command", Severity.HIGH, "Shuts down or reboots the machine", owasp, atlas, cmd))
        if hit := _first(_SQL_DROP, cmd):
            out.append(_f("destructive_command", Severity.HIGH, f"Drops or truncates database objects ({hit.strip()})", owasp, atlas, cmd))
        if hit := _first(_SQL_DELETE_ALL, cmd):
            out.append(_f("destructive_command", Severity.HIGH, "Deletes every row of a table (DELETE with no WHERE)", owasp, atlas, cmd))
        for pattern, msg in _HIGH_CMDS:
            if pattern.search(cmd):
                out.append(_f("destructive_command", Severity.HIGH, msg, owasp, atlas, cmd))
        for pattern, msg in _MEDIUM_CMDS:
            if pattern.search(cmd):
                out.append(_f("destructive_command", Severity.MEDIUM, msg, owasp, atlas, cmd))
    elif _DESTRUCTIVE_TOOL.search(call.tool) and not is_file_write(call):
        out.append(_f("destructive_command", Severity.MEDIUM, f"Calls a destructive tool ({call.tool})", owasp, atlas, call.text()))
    elif is_file_write(call) and re.search(r"(?i)delete", call.tool):
        path = target_path(call) or ""
        if path and ctx.outside_workspace(path):
            out.append(_f("destructive_command", Severity.HIGH, f"Deletes a file outside the workspace ({path})", owasp, atlas, path))
    return out


# --------------------------------------------------------------------------- #
# 3. Credential and secret access (Nx, OpenClaw token theft, ClawHavoc stealers)
# --------------------------------------------------------------------------- #

_SECRET_PATHS_HIGH = re.compile(
    r"(~|\$HOME|/home/[^/\s]+|/Users/[^/\s]+|/root)?/?\.(ssh/|aws/credentials|aws/config|gnupg/|kube/config|docker/config\.json|git-credentials|netrc|npmrc|pypirc|config/gh/hosts\.yml|config/gcloud/|azure/)"
    r"|\bid_(rsa|ed25519|ecdsa|dsa)\b|wallet\.dat|\bkeystore\b|\.electrum|solana/id\.json|metamask|Library/Keychains|login\.keychain"
    r"|\bsecurity\s+find-(generic|internet)-password|\bgh\s+auth\s+token\b|/proc/self/environ|\bcat\s+/etc/shadow"
)
_DOTENV = re.compile(r"(^|[\s/\"'])\.env(\.[\w-]+)?(\s|$|[\"'])")
_ENV_DUMP = re.compile(r"(^|[;&|]\s*)(printenv|env|set)\s*($|[;&|>])")
_SECRET_HUNT = re.compile(r"(?i)\b(grep|rg|find|ag)\b[^;&|]*(password|secret|api[_-]?key|token|private[_-]?key|mnemonic|seed phrase|wallet)[^;&|]*\s(/|~|\$HOME)(\s|$|/)")
SECRET_VALUE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|npm_[A-Za-z0-9]{36})"
)


@detector("credential_access")
def credential_access(ctx: Context) -> list[Finding]:
    call = ctx.call
    text = command_text(call) if is_shell(call) else (target_path(call) or call.text())
    out: list[Finding] = []
    owasp, atlas = ["ASI03"], ["AML.T0055"]
    if hit := _first(_SECRET_PATHS_HIGH, text):
        out.append(_f("credential_access", Severity.HIGH, f"Reads credentials or keys ({hit.strip()})", owasp, atlas, text))
    elif is_shell(call) and _first(_ENV_DUMP, text):
        out.append(_f("credential_access", Severity.MEDIUM, "Dumps all environment variables (may contain secrets)", owasp, atlas, text))
    elif _first(_DOTENV, text) and not is_file_write(call):
        out.append(_f("credential_access", Severity.MEDIUM, "Reads a .env secrets file", owasp, atlas, text))
    if is_shell(call) and (hit := _first(_SECRET_HUNT, text)):
        out.append(_f("credential_access", Severity.HIGH, "Searches the whole machine for secrets or wallets", owasp, atlas, hit))
    return out


# --------------------------------------------------------------------------- #
# 4. Exfiltration (EchoLeak, postmark-mcp, OpenClaw token theft)
# --------------------------------------------------------------------------- #

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_UPLOAD_FLAGS = re.compile(r"(\s-d\s|\s--data(-raw|-binary|-urlencode)?[\s=]|\s-F\s|\s--form[\s=]|\s-T\s|\s--upload-file[\s=]|\s-X\s*(POST|PUT)\b|--post-(data|file)[\s=]|\s@[\w~./-]+)", re.I)
_RAW_SOCKET = re.compile(r"\b(nc|ncat|netcat|socat|telnet)\s+[\w.-]+\s+\d+|/dev/tcp/")
_REMOTE_COPY = re.compile(r"\b(scp|rsync|sftp)\b[^;&|]*\s[\w.-]+@?[\w.-]+:")
_EMAIL_ADDR = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]+")


def _hosts(text: str) -> list[tuple[str, str]]:
    out = []
    for url in _URL.findall(text):
        try:
            host = urlparse(url).hostname or ""
        except ValueError:
            continue
        if host:
            out.append((host, url))
    return out


def _emails(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [e for v in value for e in _emails(v)]
    return [m.group(0) for m in _EMAIL_ADDR.finditer(str(value))]


@detector("exfiltration")
def exfiltration(ctx: Context) -> list[Finding]:
    call, pol = ctx.call, ctx.policy
    out: list[Finding] = []
    owasp, atlas = ["ASI01", "ASI02"], ["AML.T0057", "AML.T0025"]
    text = command_text(call) if is_shell(call) else call.text()
    unknown = [(h, u) for h, u in _hosts(text) if not pol.domain_allowed(h)]

    # Secrets leaving through any outbound channel
    outbound = is_message_send(call) or bool(unknown) or bool(_RAW_SOCKET.search(text))
    if outbound and (hit := _first(SECRET_VALUE, text)):
        out.append(_f("exfiltration", Severity.CRITICAL, "Sends what looks like a secret key off the machine", owasp, atlas, hit[:12] + "..."))

    if is_shell(call):
        if unknown and _UPLOAD_FLAGS.search(text):
            host = unknown[0][0]
            sev = Severity.CRITICAL if ctx.state.secret_touched else Severity.HIGH
            out.append(_f("exfiltration", sev, f"Uploads data to an unapproved host ({host})", owasp, atlas, text))
        if hit := _first(_RAW_SOCKET, text):
            out.append(_f("exfiltration", Severity.HIGH, "Opens a raw network socket to a remote host", owasp, atlas, hit))
        if hit := _first(_REMOTE_COPY, text):
            out.append(_f("exfiltration", Severity.MEDIUM, "Copies files to a remote machine", owasp, atlas, hit))
    elif unknown and not is_message_send(call):
        # A fetch or browse to an unknown host carrying a large query string (EchoLeak-style)
        for host, url in unknown:
            query = urlparse(url).query
            if len(query) >= 80 or SECRET_VALUE.search(query):
                sev = Severity.CRITICAL if ctx.state.secret_touched or ctx.state.taint == "injected" else Severity.HIGH
                out.append(_f("exfiltration", sev, f"Sends data inside a URL to an unapproved host ({host})", owasp, atlas, url))
                break

    if is_email_send(call):
        bcc = _emails(call.args.get("bcc"))
        external_bcc = [e for e in bcc if not pol.email_domain_allowed(e.split("@", 1)[1])]
        if external_bcc:
            out.append(_f("exfiltration", Severity.HIGH, f"Silently BCCs an external address ({external_bcc[0]})", owasp + ["ASI04"], atlas, ", ".join(external_bcc)))
        if pol.allowed_email_domains:
            recips = _emails(call.args.get("to")) + _emails(call.args.get("cc"))
            new = [e for e in recips if not pol.email_domain_allowed(e.split("@", 1)[1])]
            if new:
                out.append(_f("exfiltration", Severity.MEDIUM, f"Emails a domain outside the allowlist ({new[0]})", owasp, atlas, ", ".join(new)))
    return out


# --------------------------------------------------------------------------- #
# 5. Supply chain and unsafe code execution (Hugging Face models, ClawHavoc, LeRobot)
# --------------------------------------------------------------------------- #

_PIPE_TO_SHELL = re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^;&]*\|\s*python[23]?\b")
_B64_EXEC = re.compile(r"base64\s+(-d|--decode|-D)\b[^;&]*\|\s*(sudo\s+)?(ba|z)?sh\b|frombase64string|eval\s*\(\s*(atob|base64)", re.I)
_PASTE_SITES = re.compile(r"(?i)\b(rentry\.(co|org)|pastebin\.com|glot\.io|hastebin\.|paste\.ee|ghostbin\.|dpaste\.|controlc\.com|transfer\.sh|0x0\.st)\b")
_QUARANTINE = re.compile(r"\bxattr\s+(-[a-z]*d[a-z]*\s+com\.apple\.quarantine|-c\b|-cr\b|-rc\b)")
_PIP_URL = re.compile(r"\bpip3?\s+install\b[^;&|]*(git\+|https?://|--index-url\s+(?!https://pypi\.org)|--extra-index-url\s)")
_NPM_URL = re.compile(r"\b(npm|pnpm|yarn)\s+(install|add|i)\b[^;&|]*\shttps?://")
_UNSAFE_DESER = re.compile(
    r"\bpickle\.loads?\(|\bcPickle\.loads?\(|\bdill\.loads?\(|\bjoblib\.load\(|\bshelve\.open\(|\bmarshal\.loads?\("
    r"|\btorch\.load\((?![^)]*weights_only\s*=\s*True)[^)]*\)|\byaml\.load\((?![^)]*Loader\s*=\s*yaml\.(Safe|CSafe)Loader)[^)]*\)|allow_pickle\s*=\s*True"
)
_NET_DESER = re.compile(r"pickle\.loads?\(\s*(request|req|data|msg|payload|conn|sock|body|recv)", re.I)
_UNPINNED_MODEL = re.compile(r"""from_pretrained\(\s*["'][\w.-]+/[\w.-]+["']\s*\)|hf_hub_download\((?![^)]*revision)[^)]*\)|huggingface-cli\s+download\s+(?![^;&|]*--revision)[^;&|]+""")
_EXTENSION_INSTALL = re.compile(r"\b(claude\s+mcp\s+add|clawhub\s+install|openclaw\s+skills?\s+install|npx\s+-y\s+\S*mcp\S*|uvx\s+\S*mcp\S*)")


@detector("supply_chain")
def supply_chain(ctx: Context) -> list[Finding]:
    call = ctx.call
    out: list[Finding] = []
    owasp, atlas = ["ASI04"], ["AML.T0010"]
    if not is_shell(call):
        return out
    cmd = command_text(call)
    if hit := _first(_B64_EXEC, cmd):
        out.append(_f("supply_chain", Severity.CRITICAL, "Decodes and runs a hidden base64 payload", owasp + ["ASI05"], atlas + ["AML.T0011"], cmd))
    if hit := _first(_PIPE_TO_SHELL, cmd):
        out.append(_f("supply_chain", Severity.HIGH, "Downloads a script and pipes it straight into a shell", owasp + ["ASI05"], atlas + ["AML.T0011"], cmd))
    if hit := _first(_PASTE_SITES, cmd):
        out.append(_f("supply_chain", Severity.HIGH, f"Pulls content from a paste site often used for malware lures ({hit})", owasp, atlas, cmd))
    if _first(_QUARANTINE, cmd):
        out.append(_f("supply_chain", Severity.HIGH, "Removes the macOS quarantine flag from a download (common infostealer step)", owasp, atlas, cmd))
    if _first(_PIP_URL, cmd) or _first(_NPM_URL, cmd):
        out.append(_f("supply_chain", Severity.MEDIUM, "Installs a package from outside the official registry", owasp, atlas, cmd))
    if hit := _first(_EXTENSION_INSTALL, cmd):
        out.append(_f("supply_chain", Severity.LOW, f"Installs a new agent skill or MCP server; review its source ({hit})", owasp, atlas, cmd))
    return out


@detector("unsafe_deserialization")
def unsafe_deserialization(ctx: Context) -> list[Finding]:
    call = ctx.call
    if is_shell(call):
        text = command_text(call)
    elif is_file_write(call):
        text = written_content(call)
    else:
        return []
    out: list[Finding] = []
    if hit := _first(_NET_DESER, text):
        out.append(_f("unsafe_deserialization", Severity.HIGH, "Unpickles data received over the network (remote code execution)", ["ASI05"], ["AML.T0011"], hit))
    elif hit := _first(_UNSAFE_DESER, text):
        out.append(_f("unsafe_deserialization", Severity.MEDIUM, f"Loads a file format that can run code ({hit[:40]})", ["ASI05", "ASI04"], ["AML.T0011"], hit))
    if hit := _first(_UNPINNED_MODEL, text):
        out.append(_f("unpinned_model", Severity.LOW, "Downloads a model without pinning a revision (namespace hijack risk)", ["ASI04"], ["AML.T0010"], hit))
    return out


# --------------------------------------------------------------------------- #
# 6. Production changes and change freezes (Replit)
# --------------------------------------------------------------------------- #

_WRITE_OPS = re.compile(
    r"(?i)\b(insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s|alter\s+table|truncate|create\s+table|migrate|db:push|deploy|apply|rollout|helm\s+upgrade|kubectl\s+(apply|delete|set|scale)|terraform\s+(apply|destroy)|git\s+push|rm\s|mv\s)"
)


@detector("production_change")
def production_change(ctx: Context) -> list[Finding]:
    call, pol = ctx.call, ctx.policy
    if not (is_shell(call) or is_file_write(call) or "sql" in call.tool.lower()):
        return []
    text = command_text(call) if not is_file_write(call) else (target_path(call) or "") + "\n" + written_content(call)
    writes = bool(_WRITE_OPS.search(text)) or is_file_write(call)
    if not writes:
        return []
    markers = [m for m in pol.production_markers if re.search(rf"(?i)(\b|_|-){re.escape(m)}(\b|_|-)", text)]
    out: list[Finding] = []
    if pol.change_freeze and (markers or not is_file_write(call)):
        out.append(_f("production_change", Severity.CRITICAL, "Makes a change while a code freeze is in effect", ["ASI03", "ASI10"], ["AML.T0048"], text))
    elif markers:
        out.append(_f("production_change", Severity.HIGH, f"Writes to a production system ({markers[0]})", ["ASI03"], ["AML.T0048"], text))
    return out


# --------------------------------------------------------------------------- #
# 7. Actions on the user's behalf: money, accounts, public posts
#    (ClawHub crypto front-running, OpenClaw dating profiles)
# --------------------------------------------------------------------------- #

_FINANCIAL = re.compile(r"(?i)(transfer|payment|pay_|purchase|checkout|buy_|swap|withdraw|send_(sol|eth|btc|crypto|funds|money)|place_order|trade)")
_FINANCIAL_CMD = re.compile(r"\b(solana\s+transfer|spl-token\s+transfer|cast\s+send|bitcoin-cli\s+send\w*|stripe\s+(charges|payouts|transfers)\s+create)\b")
_IDENTITY = re.compile(r"(?i)\b(sign ?up|register( account| user)?|create (account|profile|post)|(post|send|publish) (tweet|status|post)|tweet create|submit form)\b")


_PAY_INTENT = {"pay", "paid", "send", "transfer", "money", "bill", "rent", "refund", "payment", "reimburse", "split",
               "settle", "invoice", "donate", "tip", "fee", "subscription", "remaining", "difference"}


_PAYEE_KEYS = {"recipient", "to", "payee", "beneficiary", "account", "iban", "name", "merchant"}


def _payment_authorized(ctx: Context) -> bool:
    """Task-bound capability check for a payment (CaMeL-style, simplified).

    Allowed without asking only when all of these hold:
    * the user's own request (seen via UserPromptSubmit or observe_user) asks for a payment;
    * the call names at least one recipient (IBAN, account, email, address...);
    * every recipient appeared in the user's request, or in tool output outside any
      instruction, or in a document the user explicitly named; and none was planted by
      an instruction in other tool output (a payee given by name must be named by the user);
    * the session has not read injected content.
    """
    state = ctx.state
    if not state.user_tokens or state.taint == "injected":
        return False
    if not ({_stem(t) for t in state.user_tokens} & {_stem(w) for w in _PAY_INTENT}):
        return False
    recipients = pv.entities(ctx.call.text())
    planted = state.instruction_entities(exclude_user_pointed=True)
    if recipients:
        allowed = set(state.user_entities) | set(state.clean_entities) | (
            state.instruction_entities() - planted)  # from a document the user named
        return recipients <= allowed and not (recipients & planted)
    # A payee given by name ("send Spotify the difference"): every word of it must be in the request.
    names = [v for k, v in ctx.call.args.items() if isinstance(v, str) and k.lower() in _PAYEE_KEYS]
    words = {w for v in names for w in pv.tokens(v)}
    return bool(words) and words <= set(state.user_tokens)


@detector("acts_on_behalf")
def acts_on_behalf(ctx: Context) -> list[Finding]:
    call = ctx.call
    out: list[Finding] = []
    text = command_text(call) if is_shell(call) else ""
    if _FINANCIAL.search(call.tool) or _first(_FINANCIAL_CMD, text):
        if _payment_authorized(ctx):
            out.append(_f("acts_on_behalf", Severity.LOW, "Moves money as the user asked, to a recipient from their request "
                          "or from clean data", ["ASI09"], [], call.text()))
        else:
            out.append(_f("acts_on_behalf", Severity.HIGH, "Moves money or crypto on the user's behalf", ["ASI09", "ASI02"], ["AML.T0048"], call.text()))
    elif _IDENTITY.search(pv.split_identifier(call.tool)) or re.search(r"(?i)https?://[^\s]*/(signup|sign-up|register|join)\b", call.text()):
        out.append(_f("acts_on_behalf", Severity.MEDIUM, "Creates an account or posts publicly as the user", ["ASI09", "ASI10"], ["AML.T0048"], call.text()))
    return out


# --------------------------------------------------------------------------- #
# 8. Workspace scope: writes outside the project
# --------------------------------------------------------------------------- #

_PERSISTENCE = re.compile(r"(\.bashrc|\.zshrc|\.bash_profile|\.profile|\.zprofile|crontab|LaunchAgents|LaunchDaemons|/etc/cron|systemd/system|\.config/autostart)")


@detector("scope_violation")
def scope_violation(ctx: Context) -> list[Finding]:
    call = ctx.call
    out: list[Finding] = []
    if is_file_write(call):
        path = target_path(call)
        if path and _PERSISTENCE.search(path):
            out.append(_f("scope_violation", Severity.HIGH, f"Modifies a startup or persistence file ({path})", ["ASI03", "ASI10"], ["AML.T0048"], path))
        elif path and ctx.outside_workspace(path):
            out.append(_f("scope_violation", Severity.MEDIUM, f"Writes outside the workspace ({path})", ["ASI03"], [], path))
    elif is_shell(call):
        cmd = command_text(call)
        if re.search(r">>?\s*(~|\$HOME)?/?\S*" + _PERSISTENCE.pattern, cmd) or re.search(r"\bcrontab\s+(-\s|\S+\.txt|-e)", cmd):
            out.append(_f("scope_violation", Severity.HIGH, "Modifies a shell startup or scheduled-task file", ["ASI03", "ASI10"], ["AML.T0048"], cmd))
    return out


# --------------------------------------------------------------------------- #
# 9. Hijack: risky actions after reading untrusted or injected content
# --------------------------------------------------------------------------- #


@detector("tainted_action")
def tainted_action(ctx: Context) -> list[Finding]:
    call, state = ctx.call, ctx.state
    if state.taint == "none":
        return []
    risky = (is_shell(call) or is_message_send(call) or is_sink(call) or bool(_FINANCIAL.search(call.tool))
             or (is_file_write(call) and ctx.outside_workspace(target_path(call) or ".")))
    if not risky:
        return []
    if state.taint == "injected":
        return [_f("tainted_action", Severity.HIGH,
                   f"Takes a risky action right after reading content with hidden instructions (from {state.taint_source})",
                   ["ASI01"], ["AML.T0051.001"], call.text())]
    # Untrusted but not obviously injected: replying after reading email is normal,
    # so this is only a low-severity breadcrumb for the audit trail.
    if is_message_send(call):
        return [_f("tainted_action", Severity.LOW,
                   f"Sends a message after reading untrusted content (from {state.taint_source})",
                   ["ASI01"], ["AML.T0051.001"], call.text())]
    return []


# --------------------------------------------------------------------------- #
# 10. Runaway behaviour: loops and floods (OpenClaw 500-message spam)
# --------------------------------------------------------------------------- #


@detector("runaway_agent")
def runaway_agent(ctx: Context) -> list[Finding]:
    call, pol, state = ctx.call, ctx.policy, ctx.state
    out: list[Finding] = []
    now = call.timestamp
    recent = [t for t in state.tool_times.get(call.tool, []) if now - t <= pol.window_seconds]
    if len(recent) + 1 > pol.max_calls_per_tool:
        out.append(_f("runaway_agent", Severity.MEDIUM, f"Called {call.tool} {len(recent) + 1} times in {pol.window_seconds}s", ["ASI10", "ASI08"], ["AML.T0029"]))
    if is_message_send(call):
        msgs = [t for t in state.message_times if now - t <= pol.window_seconds]
        if len(msgs) + 1 > pol.max_messages:
            out.append(_f("runaway_agent", Severity.HIGH, f"Sent {len(msgs) + 1} messages in {pol.window_seconds}s (possible spam loop)", ["ASI10"], ["AML.T0029"]))
    sig = state.signature(call)
    repeats = 1
    for prev in reversed(state.last_calls):
        if prev != sig:
            break
        repeats += 1
    if repeats >= pol.max_identical_calls:
        out.append(_f("runaway_agent", Severity.MEDIUM, f"Repeated the identical call {repeats} times in a row (stuck in a loop)", ["ASI10", "ASI08"], ["AML.T0029"]))
    return out


# --------------------------------------------------------------------------- #
# 11. Instruction provenance: the agent does what injected data told it to
# --------------------------------------------------------------------------- #


@detector("data_instruction_followed")
def data_instruction_followed(ctx: Context) -> list[Finding]:
    state, call = ctx.state, ctx.call
    if not state.data_instructions:
        return []
    arg_text = call.text()
    call_entities = pv.entities(arg_text)
    tool_words = {_stem(w) for w in pv.tokens(pv.split_identifier(call.tool))}
    call_words = tool_words | {_stem(w) for w in pv.tokens(arg_text)}
    user_entities = set(state.user_entities)
    user_words = {_stem(w) for w in state.user_tokens}
    best: Finding | None = None
    for ins in state.data_instructions:
        if state.user_pointed(ins):
            continue  # the user asked the agent to act on this document
        ins_words = {_stem(w) for w in ins["tokens"]}
        shared_entities = (call_entities & set(ins["entities"])) - user_entities
        shared_tool_words = (tool_words & ins_words) - user_words
        shared_action = shared_tool_words & _SINK_WORDS
        shared_words = (call_words & ins_words) - user_words
        # An entity planted by an obvious injection is suspicious wherever it is used
        # (even a "read" like fetching a URL leaks data); one from an ordinary
        # embedded request only when the call changes something.
        if shared_entities and (ins["strength"] == "strong" or is_sink(call) or is_message_send(call) or is_shell(call)):
            sev = Severity.HIGH
            why = f"uses {sorted(shared_entities)[0]}, which appeared only in instructions inside {ins['source']} output"
        elif shared_action and len(shared_words) >= 2:
            sev = Severity.HIGH if ins["strength"] == "strong" else Severity.MEDIUM
            why = f"performs '{sorted(shared_action)[0]}' as requested by text inside {ins['source']} output, not by the user"
        else:
            continue
        if ins["strength"] == "strong":
            sev = Severity.HIGH
        f = _f("data_instruction_followed", sev, f"Agent appears to follow instructions planted in data: it {why}",
               ["ASI01", "ASI06"], ["AML.T0051.001"], arg_text)
        if best is None or f.severity > best.severity:
            best = f
    return [best] if best else []


# --------------------------------------------------------------------------- #
# Custom rules from the policy file
# --------------------------------------------------------------------------- #


def custom_rules(ctx: Context) -> list[Finding]:
    out = []
    for rule in ctx.policy.custom_rules:
        if rule.tools and not rule.tools.search(ctx.call.tool):
            continue
        text = ctx.call.text()
        if m := rule.pattern.search(text):
            out.append(_f(rule.id, rule.severity, rule.message, rule.owasp, [], m.group(0)))
    return out


# --------------------------------------------------------------------------- #
# Result inspection: prompt injection hidden in tool output
# --------------------------------------------------------------------------- #

INJECTION = re.compile(
    r"(?i)(ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
    r"|disregard\s+(all\s+|your\s+)?(previous|prior|above)?\s*(instructions|guidelines|rules)"
    r"|forget\s+(all\s+)?(your|previous)\s+instructions"
    r"|you\s+are\s+now\s+(in\s+)?(developer|dan|unrestricted|admin)"
    r"|new\s+(system\s+)?instructions\s*:"
    r"|\b(assistant|ai agent|ai model|llm|copilot)\s*[,:]?\s*(you\s+must|please)\s+(now\s+)?(run|execute|send|forward|delete|fetch|visit|open)"
    r"|do\s+not\s+(tell|inform|mention\s+this\s+to)\s+the\s+user"
    r"|without\s+(asking|telling|notifying)\s+the\s+user"
    r"|<\s*(system|instructions?|important)\s*>"
    r"|run\s+the\s+following\s+(shell\s+)?command)"
)


def inspect_result(tool: str, result_text: str) -> list[Finding]:
    out = []
    if m := (INJECTION.search(result_text or "") or pv.STRONG.search(result_text or "")):
        out.append(_f("prompt_injection", Severity.MEDIUM,
                      f"Tool output from {tool} contains instructions aimed at the agent",
                      ["ASI01", "ASI06"], ["AML.T0051.001"], m.group(0)))
    return out
