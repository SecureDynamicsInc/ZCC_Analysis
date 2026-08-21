"""Query language — Slice 2 of the Log-Analyzer rebuild (2026-08-07).

A minimal ZCC-aware search language over `IndexedLine` records. Pure
library — no streamlit deps — so the Slice-6 CLI can share it.

## Grammar (v1)

```
    query := or_expr
    or_expr := and_expr ("OR" and_expr)*
    and_expr := unary (("AND" | ε) unary)*        # AND is implicit
    unary := "NOT" unary | atom
    atom := "(" or_expr ")"
          | field ":" value
          | "/" regex "/"
          | quoted_text
          | bare_text
```

## Supported field primitives (v1)

Direct fields on IndexedLine:
    `component:` `level:` `pid:` `tid:` `session_id:` `host:`
    `source_file:` `contains:` `re:`

Time filter (accepts UTC or `-HHMM` offsets):
    `time:2026-07-07T14:00..2026-07-07T15:00`
    `time:2026-07-07 18:02 UTC ± 5min`   (or `+/-`, `+-`)

Derived-from-body shortcuts (regex-extracted per-line):
    `event:auth_transition|mtunnel_setup|mtunnel_close|
           broker_redirect|power_change|saml_expired|
           service_start|network_change|dc_changed|
           trust_state_change|captive_portal|dtls_fallback|
           kerberos_lookup|policy_push|pac_download|
           tray_notification|wfp_sublayer|posture_result`
    `err_code:NNN`        (matches `err_code=NNN` or `err_code:NNN`)
    `code:STRING`         (matches known code identifier in body)

Bare word or quoted string with no field prefix = case-insensitive
body substring match. `/pat/` = regex against the body.

## Deferred to Slice 3+

Fields that require IndexedLine schema extension (broker_session,
mtunnel_id, tag_id, transport, cloud, sme_ip, auth_state, trust_state,
os, zcc_version, tenant, app, connector, etc.) will land when we
extend the row model. This slice covers what the current IndexedLine
already supports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, List, Optional, Sequence, Tuple, Union


# --------------------------------------------------------------------------
# AST
# --------------------------------------------------------------------------

@dataclass
class QueryNode:
    """Base class. Subclasses override .matches(line) -> bool."""

    def matches(self, line) -> bool:  # noqa: D401
        raise NotImplementedError


@dataclass
class AndNode(QueryNode):
    children: List[QueryNode]

    def matches(self, line) -> bool:
        return all(c.matches(line) for c in self.children)


@dataclass
class OrNode(QueryNode):
    children: List[QueryNode]

    def matches(self, line) -> bool:
        return any(c.matches(line) for c in self.children)


@dataclass
class NotNode(QueryNode):
    child: QueryNode

    def matches(self, line) -> bool:
        return not self.child.matches(line)


@dataclass
class TextMatch(QueryNode):
    """Case-insensitive substring match on `line.body`."""
    needle: str

    def matches(self, line) -> bool:
        body = (line.body or "")
        return self.needle.lower() in body.lower()


@dataclass
class RegexMatch(QueryNode):
    """Regex match on `line.body`."""
    pattern: re.Pattern

    def matches(self, line) -> bool:
        return bool(self.pattern.search(line.body or ""))


@dataclass
class FieldEquals(QueryNode):
    """Case-insensitive equality on a scalar IndexedLine field."""
    field_name: str
    value: str

    def matches(self, line) -> bool:
        v = getattr(line, self.field_name, None)
        if v is None:
            return False
        return str(v).lower() == self.value.lower()


@dataclass
class FieldContains(QueryNode):
    """Case-insensitive substring match on a scalar IndexedLine field."""
    field_name: str
    needle: str

    def matches(self, line) -> bool:
        v = getattr(line, self.field_name, None)
        if v is None:
            return False
        return self.needle.lower() in str(v).lower()


@dataclass
class TimeRange(QueryNode):
    """Match if `line.ts` falls in [start, end]."""
    start: datetime
    end: datetime

    def matches(self, line) -> bool:
        ts = getattr(line, "ts", None)
        if ts is None:
            return False
        return self.start <= ts <= self.end


@dataclass
class ErrCodeMatch(QueryNode):
    """Match if body contains err_code=NNN (or err_code:NNN, error 5008, etc)."""
    code: int

    _re: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        # `err_code=5008`, `err_code: 5008`, `error 5008`, `errcode=5008`
        self._re = re.compile(
            rf"(?:err[_ ]?code\s*[:=]\s*|error\s+){self.code}\b",
            re.IGNORECASE,
        )

    def matches(self, line) -> bool:
        return bool(self._re.search(line.body or ""))


@dataclass
class CodeMatch(QueryNode):
    """Match if body contains the given code identifier as a whole token.

    Case-sensitive. Used for symbolic codes like BRK_MT_SETUP_FAIL_SAML_EXPIRED,
    ZPN_ERR_DNS_CHECK_NO_ASSISTANT, or numeric ones bare like `5008`.
    """
    code: str
    _re: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        self._re = re.compile(rf"\b{re.escape(self.code)}\b")

    def matches(self, line) -> bool:
        return bool(self._re.search(line.body or ""))


# Event classifier — well-known regex patterns per event class.
# Each entry: event_name -> re.Pattern
_EVENT_PATTERNS = {
    "auth_transition":
        re.compile(
            r"auth.*state.*(?:AUTHENTICATED|AUTHENTICATION_REQUIRED)"
            r"|zpn.*auth.*state|Auth::.*State",
            re.IGNORECASE,
        ),
    "mtunnel_setup":
        re.compile(r"mtunnel[_ ]?(?:setup|request|open|start)|BRK_MT_SETUP",
                   re.IGNORECASE),
    "mtunnel_close":
        re.compile(r"mtunnel[_ ]?(?:close|end|terminate)|BRK_MT_(?:CLOSED|TERMINATED)|zpn_mtunnel_end",
                   re.IGNORECASE),
    "broker_redirect":
        re.compile(r"BRK_REDIRECT|broker.*redirect|BRK_MT_.*BALANCE",
                   re.IGNORECASE),
    "power_change":
        re.compile(r"Power Change Event|Modern Standby|force_reauth_sleep_trigger",
                   re.IGNORECASE),
    "saml_expired":
        re.compile(r"SAML_EXPIRED|saml.*expir|saml force expired",
                   re.IGNORECASE),
    "service_start":
        re.compile(r"service (?:started|starting|initialized)|ZSAService (?:up|start)|ZCC (?:starting|up)",
                   re.IGNORECASE),
    "network_change":
        re.compile(r"network[_ ](?:change|transition|state)|adapter (?:up|down|state)",
                   re.IGNORECASE),
    "dc_changed":
        re.compile(r"zcc_tunnel.*dc_changed|SME.*chang|Service Edge.*chang",
                   re.IGNORECASE),
    "trust_state_change":
        re.compile(r"trusted[_ ]?network.*(?:enter|exit|change)|OFF_TRUSTED|NON_TRUSTED|TRUSTED_NETWORK",
                   re.IGNORECASE),
    "captive_portal":
        re.compile(r"captive[_ ]?portal", re.IGNORECASE),
    "cert_expiry_check":
        re.compile(r"getCertExpiryDaySec|cert.*expir", re.IGNORECASE),
    "dtls_fallback":
        re.compile(r"DTLS.*(?:fallback|fail).*TLS|falling back to TLS",
                   re.IGNORECASE),
    "kerberos_lookup":
        re.compile(r"_kerberos\._tcp|kerberos.*SRV|_ldap\._tcp|_gc\._tcp",
                   re.IGNORECASE),
    "policy_push":
        re.compile(
            r"zpn_(?:trusted_networks|posture_profile|forwarding_profile)_ack"
            r"|TrayPolicy::serialize|policy.*push",
            re.IGNORECASE,
        ),
    "pac_download":
        re.compile(r"PAC.*(?:download|fetch)|pac_download|PACFile", re.IGNORECASE),
    "tray_notification":
        re.compile(r"send ZSATray Notification|tray.*notif", re.IGNORECASE),
    "wfp_sublayer":
        re.compile(r"WFP.*SubLayer|ZEVENT_FW_SUBLAYER_WEIGHT_MISMATCH|SenseNdr",
                   re.IGNORECASE),
    "posture_result":
        re.compile(r"posture.*(?:pass|fail|result)|POSTURE_CHECK", re.IGNORECASE),
}


@dataclass
class EventMatch(QueryNode):
    """Match if body matches the regex for `event_name`."""
    event_name: str
    _re: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def __post_init__(self):
        pat = _EVENT_PATTERNS.get(self.event_name)
        if pat is None:
            raise QueryError(
                f"Unknown event: {self.event_name!r}. "
                f"Known: {sorted(_EVENT_PATTERNS)}"
            )
        self._re = pat

    def matches(self, line) -> bool:
        return bool(self._re.search(line.body or ""))


def known_events() -> List[str]:
    """Return the sorted list of `event:` names the query language knows."""
    return sorted(_EVENT_PATTERNS)


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class QueryError(ValueError):
    """Raised when a query string is malformed or references unknown fields."""


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

# Token kinds
_T_LPAREN = "LPAREN"
_T_RPAREN = "RPAREN"
_T_AND = "AND"
_T_OR = "OR"
_T_NOT = "NOT"
_T_ATOM = "ATOM"           # bare word, quoted string, field:value, /re/


@dataclass
class _Token:
    kind: str
    text: str


_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_REGEX_RE = re.compile(r"/((?:[^/\\]|\\.)*)/")
_BAREWORD_RE = re.compile(r"[^\s()]+")


def tokenize(q: str) -> List[_Token]:
    """Break `q` into tokens. Preserves quoted strings and /regex/ atoms
    as single ATOM tokens with their delimiters stripped."""
    tokens: List[_Token] = []
    i = 0
    n = len(q)
    while i < n:
        c = q[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(_Token(_T_LPAREN, "("))
            i += 1
            continue
        if c == ")":
            tokens.append(_Token(_T_RPAREN, ")"))
            i += 1
            continue
        if c == '"':
            m = _QUOTED_RE.match(q, i)
            if not m:
                raise QueryError(f"Unterminated quoted string at position {i}")
            # Preserve quotes on the token — the atom parser needs to know
            # this is quoted text (not a field:value).
            tokens.append(_Token(_T_ATOM, m.group(0)))
            i = m.end()
            continue
        if c == "/":
            m = _REGEX_RE.match(q, i)
            if not m:
                raise QueryError(f"Unterminated regex at position {i}")
            tokens.append(_Token(_T_ATOM, m.group(0)))
            i = m.end()
            continue
        # Bare word (may contain : for field:value; may contain -, _, ., etc.)
        m = _BAREWORD_RE.match(q, i)
        if not m:
            raise QueryError(f"Unexpected character {c!r} at position {i}")
        word = m.group(0)
        # Keyword-cased operators
        upper = word.upper()
        if upper == "AND":
            tokens.append(_Token(_T_AND, "AND"))
        elif upper == "OR":
            tokens.append(_Token(_T_OR, "OR"))
        elif upper == "NOT":
            tokens.append(_Token(_T_NOT, "NOT"))
        else:
            tokens.append(_Token(_T_ATOM, word))
        i = m.end()
    return tokens


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

# Direct-field IndexedLine primitives that map to FieldEquals or FieldContains.
# Value is (attr_name, "equals" | "contains").
_DIRECT_FIELDS = {
    "component": ("component", "equals"),
    "level": ("level", "equals"),
    "pid": ("pid", "equals"),
    "tid": ("tid", "equals"),
    "session_id": ("session_id", "contains"),
    "host": ("host", "contains"),
    "source_file": ("source_file", "contains"),
}


def _parse_atom_token(text: str) -> QueryNode:
    """Turn a single ATOM token's text into a QueryNode."""
    # Regex atom: /pattern/
    if text.startswith("/") and text.endswith("/") and len(text) >= 2:
        pat = text[1:-1]
        try:
            return RegexMatch(re.compile(pat, re.IGNORECASE))
        except re.error as e:
            raise QueryError(f"Bad regex {pat!r}: {e}") from e
    # Quoted text: "hello world" → substring match on body
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        inner = text[1:-1].replace("\\\"", "\"").replace("\\\\", "\\")
        return TextMatch(inner)
    # field:value?
    if ":" in text:
        key, _, val = text.partition(":")
        if key and val:
            return _parse_field(key.lower(), val)
    # Bare word → substring on body
    return TextMatch(text)


def _parse_field(key: str, val: str) -> QueryNode:
    """Turn `key:val` into a QueryNode. Handles all known field primitives."""
    # Strip surrounding quotes on the value, if present.
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        val = val[1:-1]

    # Direct-field primitives
    if key in _DIRECT_FIELDS:
        attr, mode = _DIRECT_FIELDS[key]
        if mode == "equals":
            return FieldEquals(attr, val)
        else:
            return FieldContains(attr, val)

    # Free-text alias
    if key == "contains":
        return TextMatch(val)

    # Regex alias
    if key == "re":
        try:
            return RegexMatch(re.compile(val, re.IGNORECASE))
        except re.error as e:
            raise QueryError(f"Bad regex {val!r}: {e}") from e

    # Time filter
    if key == "time":
        return _parse_time(val)

    # Event shortcut
    if key == "event":
        return EventMatch(val.strip())

    # err_code:NNN
    if key == "err_code":
        try:
            n = int(val)
        except ValueError as e:
            raise QueryError(f"err_code expects an integer, got {val!r}") from e
        return ErrCodeMatch(n)

    # code:XXXX (symbolic or numeric identifier as a whole token)
    if key == "code":
        return CodeMatch(val.strip())

    raise QueryError(
        f"Unknown field {key!r}. "
        f"Known: {sorted(list(_DIRECT_FIELDS) + ['contains', 're', 'time', 'event', 'err_code', 'code'])}"
    )


# ---- Time-range parsing --------------------------------------------------

_TS_FMTS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d",
]


def _parse_ts(s: str) -> datetime:
    """Parse a bare timestamp. Result is UTC-aware."""
    s = s.strip()
    for fmt in _TS_FMTS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise QueryError(f"Bad timestamp {s!r}")


_DUR_RE = re.compile(r"^\s*(\d+)\s*(s|sec|second|m|min|minute|h|hr|hour|d|day)s?\s*$",
                     re.IGNORECASE)


def _parse_duration(s: str) -> timedelta:
    """Parse `5min`, `30s`, `1h`, `2d`."""
    m = _DUR_RE.match(s)
    if not m:
        raise QueryError(f"Bad duration {s!r}")
    n = int(m.group(1))
    unit = m.group(2).lower()
    if unit.startswith("s"):
        return timedelta(seconds=n)
    if unit.startswith("m") and not unit.startswith("mo"):
        return timedelta(minutes=n)
    if unit.startswith("h"):
        return timedelta(hours=n)
    if unit.startswith("d"):
        return timedelta(days=n)
    raise QueryError(f"Bad duration unit in {s!r}")


def _parse_time(val: str) -> TimeRange:
    """Time filter grammar:
      time:START..END              (both bounds explicit)
      time:CENTER±DUR              (± window)
      time:CENTER+-DUR             (ascii alternative for ±)
      time:CENTER+/-DUR
    Timestamps: YYYY-MM-DD[ Thh:mm[:ss]]  — assumed UTC.
    """
    val = val.strip()

    if ".." in val:
        left, _, right = val.partition("..")
        start = _parse_ts(left)
        end = _parse_ts(right)
        if end < start:
            start, end = end, start
        return TimeRange(start, end)

    # ± window
    for sep in ("±", "+-", "+/-"):
        if sep in val:
            left, _, right = val.partition(sep)
            centre = _parse_ts(left)
            dur = _parse_duration(right)
            return TimeRange(centre - dur, centre + dur)

    # Single timestamp = 1-second window at that ts.
    centre = _parse_ts(val)
    return TimeRange(centre, centre + timedelta(seconds=1))


# ---- Recursive-descent parser -------------------------------------------

class _Parser:
    def __init__(self, tokens: Sequence[_Token]):
        self.tokens = list(tokens)
        self.pos = 0

    def _peek(self) -> Optional[_Token]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> _Token:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse(self) -> QueryNode:
        node = self._parse_or()
        if self._peek() is not None:
            raise QueryError(f"Unexpected trailing token {self._peek().text!r}")
        return node

    def _parse_or(self) -> QueryNode:
        left = self._parse_and()
        children = [left]
        while self._peek() is not None and self._peek().kind == _T_OR:
            self._consume()
            children.append(self._parse_and())
        return children[0] if len(children) == 1 else OrNode(children)

    def _parse_and(self) -> QueryNode:
        children = [self._parse_unary()]
        while True:
            tok = self._peek()
            if tok is None:
                break
            if tok.kind == _T_AND:
                self._consume()
                children.append(self._parse_unary())
                continue
            # Implicit AND: two adjacent atoms/(NOT/LPAREN) chain together.
            if tok.kind in (_T_ATOM, _T_NOT, _T_LPAREN):
                children.append(self._parse_unary())
                continue
            break
        return children[0] if len(children) == 1 else AndNode(children)

    def _parse_unary(self) -> QueryNode:
        tok = self._peek()
        if tok is None:
            raise QueryError("Unexpected end of query")
        if tok.kind == _T_NOT:
            self._consume()
            return NotNode(self._parse_unary())
        return self._parse_atom()

    def _parse_atom(self) -> QueryNode:
        tok = self._peek()
        if tok is None:
            raise QueryError("Expected atom, got end of query")
        if tok.kind == _T_LPAREN:
            self._consume()
            node = self._parse_or()
            close = self._peek()
            if close is None or close.kind != _T_RPAREN:
                raise QueryError("Missing closing paren")
            self._consume()
            return node
        if tok.kind == _T_ATOM:
            self._consume()
            return _parse_atom_token(tok.text)
        raise QueryError(f"Unexpected token {tok.text!r}")


def parse_query(q: str) -> QueryNode:
    """Top-level: parse a query string into an AST."""
    if not q or not q.strip():
        raise QueryError("Empty query")
    tokens = tokenize(q)
    if not tokens:
        raise QueryError("Empty query")
    return _Parser(tokens).parse()


# --------------------------------------------------------------------------
# Evaluator entry point
# --------------------------------------------------------------------------

def find_matches(
    idx,                                 # LogIndex (duck-typed: .lines)
    query_str: str,
    limit: Optional[int] = None,
) -> Iterator:
    """Yield IndexedLine records matching `query_str`. Stops after `limit`
    if given. Streaming — never materialises the full result list."""
    node = parse_query(query_str)
    yielded = 0
    for line in idx.lines:
        if node.matches(line):
            yield line
            yielded += 1
            if limit is not None and yielded >= limit:
                return
