"""Instruction provenance: did the agent act on instructions that came from data?

Prompt injection works by planting instructions in content the agent reads
(emails, web pages, files, tool output). Instead of only asking "does this text
look like an injection?", we also ask "is the agent now doing what that text
told it to do, and not what the user asked?". This is a lightweight, lexical
version of the task-alignment idea behind LlamaFirewall's AlignmentCheck and
the data-flow tracking in CaMeL and FIDES: no model call, microseconds per check.

* Instructions found in tool output are stored per session with their
  strength (strong = classic injection phrasing, weak = an embedded request).
* The user's own prompt, when the integration can see it, is stored as trusted
  intent.
* A later tool call that reuses an entity (email, URL, account number, crypto
  address) or the action words of a stored instruction, and that the user's
  prompt does not account for, is flagged.
"""

from __future__ import annotations

import re

_EMAIL = re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}")
_URL = re.compile(r"(?i)\b(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+(?:com|org|net|io|co|uk|de|info|biz|xyz|ai|app|dev|me|us|ru|cn|top|site|online))\b(?:/[^\s\"'<>,)]*)?")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
_ACCOUNT = re.compile(r"\b(?!\d{4}-\d{2}-\d{2}\b)(?!(?:19|20)\d{6}\b)\d[\d-]{7,}\d\b")
# Domains so common that seeing them in data and in a call means nothing
_COMMON_DOMAINS = set("""gmail.com googlemail.com outlook.com hotmail.com yahoo.com icloud.com proton.me protonmail.com
aol.com live.com msn.com google.com amazon.com facebook.com twitter.com x.com github.com microsoft.com apple.com
linkedin.com youtube.com wikipedia.org example.com""".split())
_CRYPTO = re.compile(r"\b(?:0x[a-fA-F0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,})\b")
_PHONE = re.compile(r"\+\d[\d\s-]{8,}\d")

_WORD = re.compile(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])")
_STOP = set("""the and for you your with that this from have will are was were been can could would should please
then them they their there here what when where which who whom how all any each into onto about after before
first also just only some more most other such than too very our ours out over under again further once both
does did doing done get got make made need needs want wants like let thanks thank hey dear regards signed
information important message task tasks solve gave beginning following follow user assistant agent model
emma johnson todo now new using use used via per its it's not but yes""".split())

# Words that describe an action with side effects. A data instruction is only
# "followed" when the call shares one of these with it.
ACTION_WORDS = set("""send sent email mail forward reply post publish share invite add remove delete erase drop wipe
transfer pay payment withdraw deposit buy purchase order sell trade grant unlock lock disable enable reset update
change modify create schedule book cancel upload download install run execute deploy push merge approve accept
transfer move copy rename write reserve rent hire register subscribe unsubscribe submit sign confirm
assign revoke invite kick ban archive purge""".split())


_DATE_LIKE = re.compile(r"\d{1,4}([-/.])\d{1,2}\1\d{1,4}")
_IDENT = re.compile(r"[A-Za-z0-9][\w.-]*(?:[._/-][\w.-]+)+|[A-Za-z]*\d[\w-]{3,}")


def identifiers(value) -> set[str]:
    """Specific names a request can point at: file names, paths, ids (bill-december-2023.txt, B08KFQ9HK5).

    Plain words are left out, so 'fetch the product details' points at nothing in particular.
    """
    if isinstance(value, dict):
        return set().union(*(identifiers(v) for v in value.values())) if value else set()
    if isinstance(value, (list, tuple)):
        return set().union(*(identifiers(v) for v in value)) if value else set()
    if not isinstance(value, str):
        return set()
    value = _URL.sub(" ", _EMAIL.sub(" ", value))  # people and sites are not documents
    return {m.group(0).lower().strip(".-") for m in _IDENT.finditer(value)
            if len(m.group(0)) >= 6 and not _DATE_LIKE.fullmatch(m.group(0))}


_FIELD = re.compile(r"""["']?[A-Za-z_][\w .-]{0,40}["']?\s*[:=]\s*["']?([^\s"',}\]]+)["']?\s*(?=[,}\]\n]|$)""", re.M)


def field_entities(text: str) -> set[str]:
    """Entities that are the whole value of a structured field (recipient: GB29..., "to": "a@b.com").

    A value buried in a sentence ("...please send it to GB29...") is prose, which is
    where injected requests live, so it does not count.
    """
    out: set[str] = set()
    for m in _FIELD.finditer(text or ""):
        out |= entities(m.group(1))
    return out


def entities(text: str) -> set[str]:
    text = text or ""
    found = {m.group(0).lower() for m in _EMAIL.finditer(text)}
    for m in _URL.finditer(text):
        found.add(m.group(1).lower().removeprefix("www."))
    found |= {m.group(0) for m in _IBAN.finditer(text)}
    found |= {m.group(0) for m in _CRYPTO.finditer(text)}
    found |= {re.sub(r"\D", "", m.group(0)) for m in _ACCOUNT.finditer(text)}
    found |= {re.sub(r"\D", "", m.group(0)) for m in _PHONE.finditer(text)}
    # Bare email domains count too, so "attacker.example" matches "x@attacker.example"
    found |= {e.split("@", 1)[1] for e in list(found) if "@" in e}
    return {e for e in found if len(e) >= 6 and e not in _COMMON_DOMAINS}


def tokens(text: str) -> set[str]:
    words = {w.lower() for w in _WORD.findall(text or "")}
    return {w for w in words if len(w) >= 3 and w not in _STOP}


def split_identifier(name: str) -> str:
    """'AugustSmartLockGrantGuestAccess' / 'send_money' -> words."""
    return " ".join(_WORD.findall(name.replace("_", " ").replace("-", " ")))


# --------------------------------------------------------------------------- #
# Finding instructions inside data
# --------------------------------------------------------------------------- #

STRONG = re.compile(
    r"(?i)(ignore\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)"
    r"|disregard\s+(all\s+|your\s+)?(previous|prior|above)?\s*(instructions|guidelines|rules)"
    r"|forget\s+(all\s+)?(your|previous)\s+instructions"
    r"|you\s+are\s+now\s+(in\s+)?(developer|dan|unrestricted|admin)"
    r"|new\s+(system\s+)?instructions\s*:"
    r"|\b(assistant|ai agent|ai model|llm|copilot|gpt-?\d\w*|claude|gemini|chatgpt)\s*[,:]?\s*(you\s+must|please)\s+(now\s+)?\w+"
    r"|do\s+not\s+(tell|inform|mention\s+this\s+to)\s+the\s+user"
    r"|without\s+(asking|telling|notifying)\s+the\s+user"
    r"|<\s*/?\s*(system|instructions?|important|information)\s*>"
    r"|run\s+the\s+following\s+(shell\s+)?command"
    r"|important\s+(message|instructions?|notice)\s+(from|for)\s+(me|you|the\s+user)"
    r"|before\s+you\s+(can\s+)?(solve|complete|continue|finish|proceed|answer|do)\b"
    r"|after\s+you\s+(do|have\s+done|finish)\s+(that|this)"
    r"|instead\s+of\s+(the\s+|your\s+)?(original|previous|user'?s?)\s+(task|request|instructions)"
    r"|\bimportant\s*!{2,}"
    r"|(^|\n)\s*#{2,}\s*\(?(system|instruction)"
    r"|(^|\n)\s*(todo|note to (the )?(ai|assistant|agent))\s*:\s*\w+"
    r"|this\s+is\s+(a\s+)?(an\s+)?(urgent|important)\s+(request|instruction|message)\s+(from|to)\s+(the\s+)?(user|admin|you))"
)

# Sentence ends, line breaks, and the boundaries between string values in JSON,
# Python-dict or YAML output, so a request hidden in one field is seen on its own.
_SEGMENT_BREAK = re.compile(r"(?<=[.!?])\s+|\n+|[\"']\s*[:,]\s*[\"']|[{}\[\]]")
_LEAD = re.compile(
    r"^[\s\"'`>*\-]*(?:[\w-]{1,30}:\s+[\"'`]?)?[\s\"'`>*\-]*(?:(?P<label>todo|note|reminder|action required|important|attention)\s*[:!-]\s*)?"
    r"(?P<polite>(?:(?:please|kindly|you\s+must|you\s+should|you\s+need\s+to|make\s+sure\s+to|go\s+ahead\s+and|"
    r"i\s+need\s+you\s+to|i\s+want\s+you\s+to|can\s+you|could\s+you|remember\s+to|don'?t\s+forget\s+to)\s+)*)"
    r"(?P<verb>[a-z]+)",
    re.I,
)
_IMPERATIVE = ACTION_WORDS | set("""retrieve get find fetch read collect gather list tell give provide concatenate visit open
go say look check search extract summarize""".split())


def _stem(w: str) -> str:
    for suf in ("ing", "ed", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)]
    return w


_ACTION_STEMS = {_stem(w) for w in ACTION_WORDS}
stem = _stem


def is_request(sentence: str) -> bool:
    """An imperative request with a side-effecting action, e.g. 'Please email the report to x@y.com'."""
    m = _LEAD.match(sentence)
    if not m:
        return False
    verb = m.group("verb").lower()
    marked = bool(m.group("label") or m.group("polite").strip())
    if not (marked or verb in _IMPERATIVE):
        return False
    words = {_stem(w.lower()) for w in _WORD.findall(sentence)}
    return bool(words & _ACTION_STEMS)


def find_instructions(text: str) -> list[tuple[str, str]]:
    """Return (strength, span) pairs for instruction-like content in tool output."""
    text = text or ""
    out: list[tuple[str, str]] = []
    for m in STRONG.finditer(text):
        out.append(("strong", text[max(0, m.start() - 200): m.end() + 1500]))
        break  # one strong span per result is enough
    for piece in _SEGMENT_BREAK.split(text):
        sentence = piece.strip(" \t'\",")
        if sentence and is_request(sentence):
            out.append(("weak", sentence[:600]))
    return out
