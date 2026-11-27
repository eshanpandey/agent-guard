"""The engine runs every detector on a tool call and turns findings into a decision."""

from __future__ import annotations

from typing import Any

from . import detectors as d
from . import provenance as pv
from .audit import AuditLog
from .models import Decision, Finding, Severity, ToolCall, Verdict
from .policy import Policy
from .state import MemoryStateStore, SessionState


def decide(mode: str, findings: list[Finding]) -> str:
    if not findings:
        return Decision.ALLOW
    top = max(f.severity for f in findings)
    if mode == "enforce":
        if top >= Severity.HIGH:
            return Decision.BLOCK
        if top >= Severity.MEDIUM:
            return Decision.ASK
    elif mode == "guard":
        if top >= Severity.CRITICAL:
            return Decision.BLOCK
        if top >= Severity.HIGH:
            return Decision.ASK
    return Decision.FLAG


class Engine:
    def __init__(self, policy: Policy | None = None, store: Any = None, audit: AuditLog | None = None) -> None:
        self.policy = policy or Policy()
        self.store = store or MemoryStateStore()
        self.audit = audit
        from .classifiers import from_config
        self.classifier = from_config(self.policy.classifier)

    # -- before a tool runs --------------------------------------------------
    def evaluate(self, call: ToolCall) -> Verdict:
        state = self.store.load(call.session_id)
        ctx = d.Context(call=call, policy=self.policy, state=state)
        findings: list[Finding] = []
        for rule_id, fn in d.REGISTRY.items():
            if rule_id in self.policy.disabled_rules:
                continue
            findings.extend(f for f in fn(ctx) if f.rule_id not in self.policy.disabled_rules)
        findings.extend(d.custom_rules(ctx))
        findings = _dedupe(findings)

        verdict = Verdict(decide(self.policy.mode, findings), findings)
        self._update_state(state, call, findings)
        self.store.save(call.session_id, state)
        if self.audit:
            self.audit.append("tool_call", call, verdict)
        return verdict

    # -- after a tool returns ------------------------------------------------
    def observe(self, call: ToolCall, result: Any) -> Verdict:
        text = result if isinstance(result, str) else ToolCall(tool="", args={"r": result}).text()
        state = self.store.load(call.session_id)
        findings = [f for f in d.inspect_result(call.tool, text) if f.rule_id not in self.policy.disabled_rules]
        if self.classifier and not findings and self.classifier.in_scope(call):
            score = self.classifier.check(text, state.user_text)
            if score is not None and score >= self.classifier.threshold:
                findings.append(Finding("prompt_injection", Severity.MEDIUM,
                                        f"Classifier ({self.classifier.backend.name}, {score:.2f}) found instructions "
                                        f"aimed at the agent in {call.tool} output", ["ASI01", "ASI06"],
                                        ["AML.T0051.001"], text[:200]))
                # Treat the whole output as one strong instruction, so reusing anything planted
                # in it (an address, an account) is caught by data_instruction_followed.
                state.add_instruction("strong", call.tool, pv.entities(text), pv.tokens(text), sorted(pv.identifiers(call.args)))
        if findings:
            state.taint_with("injected", call.tool)
        elif d.is_untrusted_source(call.tool):
            state.taint_with("untrusted", call.tool)
        instructions = pv.find_instructions(text)
        source_ref = pv.identifiers(call.args)
        in_spans: set[str] = set()
        for strength, span in instructions:
            ents = pv.entities(span)
            in_spans |= ents
            state.add_instruction(strength, call.tool, ents, pv.tokens(span), sorted(source_ref))
        if not findings and not any(strength == "strong" for strength, _ in instructions):
            # Values outside any instruction, in output with no injection, count as ordinary
            # data the user's task can use (e.g. an IBAN in the transaction history).
            state.add_clean_entities(pv.entities(text) - in_spans)
        self.store.save(call.session_id, state)
        # Injected content is never blocked itself: we flag it and watch what the agent does next.
        verdict = Verdict(Decision.FLAG if findings else Decision.ALLOW, findings)
        if self.audit and findings:
            self.audit.append("tool_result", call, verdict)
        return verdict

    # -- what the user asked for --------------------------------------------
    def observe_user(self, session_id: str, prompt: str) -> None:
        """Record the user's request as trusted intent (e.g. from a UserPromptSubmit hook)."""
        state = self.store.load(session_id)
        state.add_user_intent(pv.entities(prompt), pv.tokens(prompt), pv.identifiers(prompt))
        state.user_text = (state.user_text + "\n" + prompt).strip()[-4000:]
        self.store.save(session_id, state)

    def _update_state(self, state: SessionState, call: ToolCall, findings: list[Finding]) -> None:
        if any(f.rule_id == "credential_access" for f in findings):
            state.secret_touched = True
        state.record(call, d.is_message_send(call), self.policy.window_seconds)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.message)
        if key not in seen or f.severity > seen[key].severity:
            seen[key] = f
    return sorted(seen.values(), key=lambda f: f.severity, reverse=True)
