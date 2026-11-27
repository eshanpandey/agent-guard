# Integrations

Agent Guard runs the same policy, detectors, session state and audit log
behind every integration. What differs is where it hooks in, and so what it
can see and how it can say no.

There are four ways in, from most to least precise:

1. **Agent hooks** (`agentguard install <agent>`): the agent itself asks Agent
   Guard before and after each tool call. Sees exactly what will run.
2. **MCP proxy** (`agentguard proxy -- <server>`): sits in front of one MCP
   server. Sees only that server's tools.
3. **API proxy** (`agentguard api-proxy`): sits between the agent and its model
   API. Works with almost anything, but sees what the model *asked for*, not
   what the agent ran.
4. **In-process** (`agentguard.sdk`, `agentguard.frameworks.*`): for people
   building their own agents.

Use hooks where the agent has them; add the API proxy for agents that don't.

## Agent hooks

Formats were checked against each vendor's hook documentation on 2026-11-27.

| | Claude Code | Codex CLI | Gemini CLI | Copilot (CLI + cloud agent) | Cursor |
| --- | --- | --- | --- | --- | --- |
| Config written | `.claude/settings.json` | `.codex/hooks.json` (`--user`: `$CODEX_HOME/hooks.json`) | `.gemini/settings.json` | `.github/hooks/agentguard.json` (`--user`: `~/.copilot/hooks/`) | `.cursor/hooks.json` |
| Before tool | `PreToolUse` | `PreToolUse` | `BeforeTool` | `preToolUse` | `beforeShellExecution` (shell) + `preToolUse` (everything else) |
| After tool | `PostToolUse` | `PostToolUse` | `AfterTool` | `postToolUse` | `postToolUse` |
| User prompt | `UserPromptSubmit` | `UserPromptSubmit` | `BeforeAgent` | `userPromptSubmitted` | `beforeSubmitPrompt` |
| Block | `permissionDecision: deny` | `permissionDecision: deny` | `decision: deny` | `permissionDecision: deny` | `permission: deny` |
| Ask a human | yes | **no**: denied with a note | **no**: denied with a note | yes in the CLI; cloud agent treats ask as deny | shell only; other tools denied with a note |
| Injection warning | `additionalContext` | `additionalContext` | `additionalContext` | `additionalContext` | `additional_context` |
| Tested | unit; live in Claude Code | **real CLI** in CI | **real CLI** in CI | **real CLI** in CI | unit tests on documented payloads |

Tool names are normalised before the detectors run (`run_shell_command`,
`exec_command`, Copilot's `bash`, Cursor's `Shell` all become `Bash`; `replace`,
`create`, `apply_patch` become `Edit`/`Write`; see
`src/agentguard/integrations/normalize.py`), so a rule written once applies to
every agent. Sessions are namespaced per agent (`codex:<id>`, `cursor:<id>`).

### Per-agent notes

**Codex CLI.** Codex only runs hooks you've reviewed: after installing, open
Codex and approve them with `/hooks`. Codex doesn't support "ask" from a
hook (it would report the hook as failed and run the tool), so calls the policy
would ask about are denied with a message telling the agent to check with the
user. If you'd rather only flag them, set `mode: monitor` in the policy, or use
Claude Code/Copilot for interactive approval. Codex's docs note that some
specialised tool paths skip hooks and that hosted tools like web search are
not covered.

**Gemini CLI.** Hooks run even in `--yolo` mode, which the end-to-end test
uses on purpose: with every approval switched off, Agent Guard is the only
check left. Gemini asks you to trust project-level hooks the first time.
Gemini strips environment variables that aren't allowlisted from hook
processes when redaction is on, and always under GitHub Actions; the installer
adds `AGENTGUARD_HOME` and `AGENTGUARD_POLICY` to
`security.environmentVariableRedaction.allowed` so a custom policy or log
location still reaches the hook. (CI caught this: the hook blocked correctly
but wrote its log to the default folder.)

**GitHub Copilot.** `.github/hooks/*.json` is read by both the Copilot CLI and
the Copilot cloud coding agent, so committing `agentguard install copilot`'s
file protects cloud-agent runs too (the cloud sandbox needs `agentguard` on
its PATH; install it in your Copilot setup steps). Copilot's command
`preToolUse` hooks are fail-closed on a non-zero exit, so the adapter always
exits 0 and states its decision in JSON. The CLI only loads repository hooks
in folders you've trusted.

**Cursor.** Untested in a real Cursor: Cursor isn't installable in our CI, so
the adapter is verified against the documented payloads only. Points we took
from the docs that a live test should confirm: `preToolUse` is documented with
allow/deny only, so non-shell "ask" verdicts are denied; Cursor blocks a
permission hook whose output isn't valid JSON, so the adapter always prints
JSON; Write/Delete `tool_input` field names aren't documented, so the
normaliser accepts `file_path`, `path`, `contents` and `content`.

**Hooks you already installed for Claude Code.** Cursor (with "Third-party
configs" on, the default) and the Copilot CLI both also read a project's
`.claude/settings.json`. If you've run `agentguard install claude-code` in a
repository, those agents already run Agent Guard through it. Installing their
native hooks as well means each call is checked twice: harmless for blocking,
but it double-counts towards rate limits. Pick one.

## API proxy

```bash
agentguard api-proxy --port 8787 [--openai-upstream URL] [--anthropic-upstream URL] [--gemini-upstream URL] [--on-ask block|allow]
```

| Format | Paths | Streaming | Tested with |
| --- | --- | --- | --- |
| OpenAI Chat Completions | `/v1/chat/completions` | yes | `openai` SDK, Copilot CLI (BYOK) |
| OpenAI Responses | `/v1/responses` | yes | `openai` SDK, Codex CLI |
| Anthropic Messages | `/v1/messages` | yes | `anthropic` SDK, Claude Code |
| Gemini | `/v1beta/models/*:generateContent`, `:streamGenerateContent` | yes | `google-genai` SDK, Gemini CLI |

What it does to each response: a tool call that's blocked is removed and
replaced by a text block saying why, and the stop reason is changed (for
example `tool_use` to `end_turn`) when no tool calls remain, so the agent's
loop stays valid. Allowed calls pass through unchanged. In a stream, text
is forwarded as it arrives; from the first tool-call event, events are held
until each call is complete and judged. Gemini sends whole calls per chunk, so
nothing is held.

What it does to each request: tool results are scanned for planted
instructions (the same check as the PostToolUse hooks), and a flagged result
gets a warning appended before it reaches the model. The user's messages are
recorded as trusted intent. Each request carries the whole conversation, so
results and messages are deduplicated per session. The session is the
`X-AgentGuard-Session` header if the client sends one, otherwise a hash of the
first user message.

What it can't do: it sees the model's request for a tool call, not the call
the agent finally runs, so an agent that rewrites commands, or runs tools
without asking the model, is out of its view. It can't ask a human, so "ask"
verdicts are blocked unless you pass `--on-ask allow`. It doesn't terminate
TLS for clients that pin the vendor's host; the client must let you set a base
URL.

## Frameworks and SDK

| Framework | Hook point | A blocked call |
| --- | --- | --- |
| LangChain / LangGraph | `guard_tools(tools)` wraps each `BaseTool` | returns the reason as the tool's output (or raises with `raise_on_block=True`) |
| OpenAI Agents SDK | the SDK's own `tool_input_guardrails` / `tool_output_guardrails` | `reject_content`: the model gets the reason; `halt_on_block=True` stops the run |
| CrewAI (1.x) | global `before_tool_call` / `after_tool_call` hooks | CrewAI's "blocked by hook" message; the reason is in the audit log |
| Plain Python | `AgentGuard.tool` decorator, or `check`/`before`/`after` | raises `ToolBlocked` |

All of them take `on_ask`: `"block"` (default), `"allow"`, or a callable that
asks someone and returns True to proceed.

## How the end-to-end tests work

`tests/fixtures/fake_llm.py` is a scripted model server that speaks all four
wire formats. On the first turn it asks for one tool call; once it sees a tool
result it answers "Done.". Every request is logged.

`tests/test_agent_e2e.py` installs Agent Guard into a throwaway home folder,
runs the real `codex exec`, `gemini -p --yolo`, `copilot -p --allow-all` and
(through the API proxy) `claude -p --permission-mode bypassPermissions`
against it, and checks two things from the request log:

* a critical command never ran, and the agent told the model Agent Guard's reason;
* a safe `cat NOTES.md` did run, and the planted instructions in the file came
  back to the model with Agent Guard's warning attached.

Each agent's own approvals are switched off in these runs, so Agent Guard is
the only thing between the model and the shell. The critical command is
`echo claude --dangerously-skip-permissions`, which is harmless if a broken
guard ever let it through. The suite skips agents whose CLI isn't installed;
CI's `agents-e2e` job installs pinned versions of all four.
