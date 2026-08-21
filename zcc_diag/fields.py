"""Generic labelled-field / key=value / embedded-JSON extractor.

Why this module exists
----------------------
Field capture used to be a hand-written regex per extractor. Measured
across the 46-bundle corpus (157,068,822 parsed lines) the logs carry
**1,735 distinct `key=value` keys and 1,033 distinct JSON keys**; a
per-field regex is a per-field chance to miss something, and three real
misses were measured:

* ``clt_bytes=182,``  — the comma before the next field ended the value
  early in the first regex written for it.
* ``rx_byptes``       — Zscaler's own typo. A regex for ``rx_bytes``
  matches nothing at all.
* the forwarding-filter table was read as 3 columns when it has **10**.
  Three successive positional regexes each matched the columns they
  were written for and silently dropped the rest.

The lesson, already proven once in ``learned.parse_route_row`` (96.6% of
142,675 real rows): **parse by label, not by position**. This module is
that idea generalised — a label engine, a `key=value` harvester, a
fault-tolerant JSON harvester, and a schema registry so that adding a
new structured record is data rather than code.

Nothing here infers, scores or ranks. Every function reports what the
text literally contains, plus honest bookkeeping about what it did NOT
find (`declared_missing`, `stops_short`, `complete`) so a caller can
tell "the log omitted this" from "the parser dropped this".

Continuation text is the main prize
-----------------------------------
27.0% of physical lines (59,339,178 of 219,677,837) carry no timestamp:
they are continuation lines of the preceding record's pretty-printed
JSON. Fourteen fields — brokerIp, brokerName, brokerType, destinationIps,
destPorts, dnsTime, pacParseTime, smeIp, smePort, nwType, requestType,
resolvedIp, bypassReason, zpaAuthState — occur ~1,061,017 times each
across 41 of 46 bundles, and most of them appear only *after* the line
break. Parsing ``line.body`` alone cannot see them. Use
``fields_for_line(store, line)``: it reads ``store.record_text(line)``
(body + continuation) and reports, per key, whether the evidence was on
the body line or in the continuation block.

Measured (this module, 5 bundles / 2,524,446 stored lines: 01, 02, 05,
12 Windows and 20 macOS)
------------------------------------------------------------------
* forwarding-filter rows: 36,137 candidate lines (physical lines
  matching the row anchor — every one of them inside a continuation
  block), 36,137 parsed = 100%; 33,750 = 93.4% carried all ten labels.
  Per-label recovery falls monotonically 100.0% (IP) -> 93.4%
  (Direction), which is the signature of the logger cutting rows at
  increasing depths, not of labels being missed: 576 rows also ended in
  a value outside the observed enum ("Global Byp", "Bypa").
* continuation-carried JSON: 91,828 field occurrences recovered that are
  absent from `line.body` entirely, over 52,582 records with
  continuation. Seven of the fourteen prize fields (destinationIps,
  dnsTime, pacParseTime, smeIp, smePort, nwType, requestType) were
  continuation-only in **100%** of their occurrences — 13,719 records
  each for the first five.
* `key=value`: 34,954 `~ZTCPServerConnection ... clt_bytes=/srv_bytes=`
  lines, 34,954 agreements with `learned.RE_TCP_CONN_CLOSE` = 100%,
  including the trailing-comma and trailing-`!` forms.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as _dc_field
from types import MappingProxyType
from typing import (
    Any, Callable, Dict, FrozenSet, Iterable, Iterator, List, Mapping,
    Optional, Pattern, Sequence, Tuple,
)

__all__ = [
    "LabelSet", "LabelParse", "parse_labelled",
    "harvest_kv", "iter_kv",
    "harvest_json", "iter_json_objects", "flatten_json",
    "harvest_json_fragments",
    "RecordSchema", "RecordMatch", "register", "get_schema",
    "schema_names", "match_schemas",
    "RecordFields", "fields_for_line",
    "FILTER_ROW", "TUNNEL_API_STATUS", "TUNNEL_STATE_JSON",
]


# =====================================================================
# 1. LABELLED FIELDS
# =====================================================================
# The shape this handles (one forwarding-filter row, whitespace as it is
# in the log):
#
#   [   0] IP: 0.0.0.0        Mask: 0.0.0.0        Adapter: Any
#          Type: Drop Inbound Filter   SRC_PORT:     0 - 0
#          DST_PORT:  9000 - 9000   Protocol: TCP   ACTION: Drop
#          IP_PROTO: IPv4   Direction: Inbound
#
# Column padding varies by build, values contain spaces ("Drop Inbound
# Filter", "0 - 0"), and the final label is regularly followed by
# nothing at all. A positional regex breaks on all three. Cutting the
# line at the *labels* is stable under every one of them: each value is
# simply "the text between my label and the next label".

_WS_RUN = re.compile(r"\s+")


def _collapse(value: str) -> str:
    """Squeeze column padding out of a value, keep internal spacing.

    ``"     0 - 0       "`` -> ``"0 - 0"``. Collapsing rather than
    deleting is deliberate: port ranges and multi-word enum values
    ("Drop Inbound Filter") have to stay readable and comparable.
    """
    return _WS_RUN.sub(" ", value).strip()


@dataclass(frozen=True)
class LabelParse:
    """Result of running a `LabelSet` over one piece of text."""

    values: Mapping[str, str]
    #: Labels in the order they physically appeared.
    order: Tuple[str, ...] = ()
    #: Declared labels that were not found at all.
    missing: Tuple[str, ...] = ()
    #: Labels found more than once (value kept is the first).
    duplicated: Tuple[str, ...] = ()
    #: True when the labels found are a strict prefix of the declared
    #: order, i.e. the text stops before the trailing labels. This is
    #: what a logger-truncated line looks like; it is a statement about
    #: the text, not a guess about intent.
    stops_short: bool = False

    def __bool__(self) -> bool:      # `if parse:` == "found anything"
        return bool(self.values)

    def get(self, label: str, default: Any = None) -> Any:
        return self.values.get(label, default)


class LabelSet:
    """A compiled set of labels that can cut any text into fields.

    ``separator`` is what follows a label (``":"`` for every ZCC table
    seen so far). ``case_sensitive`` defaults to True on purpose: ZCC
    label casing is stable, and ``re.IGNORECASE`` has already cost this
    project hours once (it folds negated character classes too, so
    ``[^T]`` silently excludes ``t`` as well).

    Labels may contain spaces (``"Sme IP"``). Longer labels are tried
    first so that a label which is a suffix of another ("IP" vs
    "Sme IP") cannot shadow it.
    """

    #: Characters a label is allowed to start right after. Without this
    #: guard "IP" would match inside "SRC_IP" or inside a value.
    BOUNDARY = r"\s\[\](),;>|"

    def __init__(self, labels: Sequence[str], *, separator: str = ":",
                 case_sensitive: bool = True,
                 require_boundary: bool = True) -> None:
        if not labels:
            raise ValueError("LabelSet needs at least one label")
        self.labels: Tuple[str, ...] = tuple(labels)
        self.separator = separator
        alts = "|".join(
            re.escape(lb) for lb in
            sorted(set(labels), key=lambda s: (-len(s), s))
        )
        pre = rf"(?:^|(?<=[{self.BOUNDARY}]))" if require_boundary else ""
        flags = re.MULTILINE if require_boundary else 0
        if not case_sensitive:
            flags |= re.IGNORECASE
        self._re: Pattern[str] = re.compile(
            pre + r"(?P<label>" + alts + r")" + re.escape(separator),
            flags,
        )

    def finditer(self, text: str) -> Iterator[re.Match]:
        return self._re.finditer(text)

    def parse(self, text: str, *, declared: Optional[Sequence[str]] = None
              ) -> LabelParse:
        """Cut `text` at every known label; value = text up to the next.

        A label present with nothing after it yields ``""`` — an empty
        string means "the logger wrote the label and no value", which is
        different from the label being absent (key not in the mapping).
        """
        hits = list(self._re.finditer(text))
        values: Dict[str, str] = {}
        order: List[str] = []
        dups: List[str] = []
        for i, mo in enumerate(hits):
            end = hits[i + 1].start() if i + 1 < len(hits) else len(text)
            label = mo.group("label")
            order.append(label)
            if label in values:
                if label not in dups:
                    dups.append(label)
                continue          # first occurrence wins, deterministically
            values[label] = _collapse(text[mo.end():end])
        want = tuple(declared) if declared is not None else self.labels
        missing = tuple(lb for lb in want if lb not in values)
        found_seq = tuple(lb for lb in want if lb in values)
        stops_short = bool(missing) and found_seq == want[:len(found_seq)]
        return LabelParse(
            values=MappingProxyType(values), order=tuple(order),
            missing=missing, duplicated=tuple(dups),
            stops_short=stops_short,
        )


def parse_labelled(text: str, labels: Sequence[str], *,
                   separator: str = ":") -> LabelParse:
    """One-shot convenience for callers that do not keep a `LabelSet`.

    Measured: compiling a 10-label alternation costs 5.3 us, parsing one
    filter row with a pre-built `LabelSet` costs 15.4 us. Keep a
    module-level `LabelSet` for hot loops — the filter table is 6,166
    rows in a single file on bundle 01, 26,305 rows across the bundle.
    """
    return LabelSet(labels, separator=separator).parse(text)


# =====================================================================
# 2. key=value HARVESTING
# =====================================================================
# The value grammar is deliberately conservative: an unquoted value ends
# at whitespace, comma or semicolon. That is what makes
# ``clt_bytes=182, srv_bytes=166!`` come out as {clt_bytes: "182",
# srv_bytes: "166"} instead of swallowing the next field.
#
# The consequence, stated rather than hidden: a value that genuinely
# contains spaces (``Error=Connection reset by peer``) is captured as
# its first token only, and a KEY that contains a space (``tx bytes =
# 100``) is captured as its last token (``bytes``). Space-bearing keys
# and values are what `LabelSet` and the schema registry are for — you
# need to know the field boundaries, and only a declared label set does.

#: Trailing characters stripped from an unquoted value. ZCC ends a
#: number of records with `!` (``srv_bytes=166!``,
#: ``destructor!!``); no measured value legitimately ends in one.
#:
#: The key names themselves are taken verbatim and never normalised.
#: `rx_byptes` is Zscaler's own typo — 34,063 occurrences, but in only
#: 2 of 46 bundles (4.3%), all macOS flow-handler destructors, and none
#: of the 26 bundles reachable in the sandbox contain it. A harvester
#: that "corrects" it to rx_bytes loses the field entirely; a regex
#: written for rx_bytes never had it in the first place.
KV_TRAILERS = "!"

_RE_KV = re.compile(
    r"(?:^|(?<=[\s\[\](),;\"']))"          # start of a token, not mid-word
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)"
    r"[ \t]*(?<![=!<>+*/-])=(?!=)[ \t]*"   # a real assignment, not ==, !=, >=
    # Space after `=` has to be allowed — ZCC writes both
    # `clt_bytes=182` and `tx bytes = 100`. The guard keeps that from
    # eating the *next* field when the value is empty: `x=  key="v"`
    # must yield x="" and key="v", not x='key="v'.
    r"(?![A-Za-z_][A-Za-z0-9_.\-]*[ \t]*=(?!=))"
    r"(?P<val>\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'|[^\s,;]*)"
)

#: Tokens containing this are skipped whole: a URL's query string is
#: full of `a=b` pairs that are part of the value, not fields of the
#: record. Measured over the 146 plain `.log` files of bundles 01/05/12/
#: 20: 9,893 of 573,429 `=` characters (1.7%) sit inside a URL token.
_RE_URLISH = re.compile(r"\S*://\S*")


def iter_kv(text: str, *, skip_urls: bool = True,
            trailers: str = KV_TRAILERS) -> Iterator[Tuple[str, str]]:
    """Yield every ``key=value`` pair in `text`, left to right."""
    if skip_urls:
        # Blank the URL out rather than deleting it, so offsets (and any
        # surrounding fields) stay where they were.
        text = _RE_URLISH.sub(lambda m: " " * len(m.group(0)), text)
    for mo in _RE_KV.finditer(text):
        raw = mo.group("val")
        if len(raw) >= 2 and raw[0] in "\"'" and raw[-1] == raw[0]:
            val = raw[1:-1]
        else:
            val = raw.rstrip(trailers) if trailers else raw
        yield mo.group("key"), val


def harvest_kv(text: str, *, skip_urls: bool = True,
               trailers: str = KV_TRAILERS) -> Dict[str, str]:
    """Every ``key=value`` pair in `text`; first occurrence wins.

    First-wins rather than last-wins so that repeating a key later in a
    long record cannot silently overwrite the value the record opened
    with. `iter_kv` gives every occurrence when that matters.
    """
    out: Dict[str, str] = {}
    for key, val in iter_kv(text, skip_urls=skip_urls, trailers=trailers):
        out.setdefault(key, val)
    return out


# =====================================================================
# 3. EMBEDDED JSON
# =====================================================================
# Two properties of ZCC's JSON make `json.loads` unusable directly:
#
#  * it is embedded in a log line, often twice
#    (``Tunnel api request: {...} response: {...}``);
#  * it is pretty-printed, so a record's object routinely opens on the
#    timestamped body line and closes several continuation lines later —
#    and the tail is frequently missing entirely, either because the
#    logger truncated the line or because the file rotated mid-record.
#
# So this is a scanner that consumes as much well-formed JSON as the
# text actually contains and returns it, marking `complete=False` when
# it ran out of text. Nothing is invented for the missing part.

_MISSING = object()          # "no value here", distinct from JSON null
_JSON_WS = " \t\r\n"
_MAX_DEPTH = 40              # deepest observed ZCC blob is 4

_RE_JSON_NUM = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f",
            "n": "\n", "r": "\r", "t": "\t"}


def _skip_ws(t: str, i: int) -> int:
    n = len(t)
    while i < n and t[i] in _JSON_WS:
        i += 1
    return i


def _scan_string(t: str, i: int) -> Tuple[str, int, bool]:
    """`t[i]` is the opening quote. Returns (value, next_i, complete)."""
    n = len(t)
    i += 1
    buf: List[str] = []
    while i < n:
        c = t[i]
        if c == "\\":
            if i + 1 >= n:
                return "".join(buf), n, False
            esc = t[i + 1]
            if esc == "u" and i + 5 < n:
                try:
                    buf.append(chr(int(t[i + 2:i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass          # not a real \uXXXX; fall through literal
            buf.append(_ESCAPES.get(esc, esc))
            i += 2
            continue
        if c == '"':
            return "".join(buf), i + 1, True
        buf.append(c)
        i += 1
    # Ran off the end mid-string: the log line was cut. Keep what we saw.
    return "".join(buf), n, False


def _scan_value(t: str, i: int, depth: int) -> Tuple[Any, int, bool]:
    i = _skip_ws(t, i)
    if i >= len(t):
        return _MISSING, i, False
    if depth > _MAX_DEPTH:
        return _MISSING, i, False
    c = t[i]
    if c == '"':
        return _scan_string(t, i)
    if c == "{":
        return _scan_object(t, i, depth)
    if c == "[":
        return _scan_array(t, i, depth)
    for lit, val in (("true", True), ("false", False), ("null", None)):
        if t.startswith(lit, i):
            return val, i + len(lit), True
    mo = _RE_JSON_NUM.match(t, i)
    if mo:
        raw = mo.group(0)
        end = mo.end()
        num: Any = float(raw) if ("." in raw or "e" in raw or "E" in raw) \
            else int(raw)
        # A number that ends exactly at end-of-text may itself have been
        # cut ("1234" logged, "12" survived). Report it, don't drop it.
        return num, end, end < len(t)
    return _MISSING, i, False


def _scan_array(t: str, i: int, depth: int) -> Tuple[List[Any], int, bool]:
    out: List[Any] = []
    i += 1
    n = len(t)
    while True:
        i = _skip_ws(t, i)
        if i >= n:
            return out, i, False
        if t[i] == "]":
            return out, i + 1, True
        if t[i] == ",":
            i += 1
            continue
        val, i, ok = _scan_value(t, i, depth + 1)
        if val is not _MISSING:
            out.append(val)
        if not ok:
            return out, i, False


def _scan_object(t: str, i: int, depth: int) -> Tuple[Dict[str, Any], int, bool]:
    out: Dict[str, Any] = {}
    i += 1
    n = len(t)
    while True:
        i = _skip_ws(t, i)
        if i >= n:
            return out, i, False
        c = t[i]
        if c == "}":
            return out, i + 1, True
        if c == ",":
            i += 1
            continue
        if c != '"':
            return out, i, False           # not JSON after all; stop here
        key, i, ok = _scan_string(t, i)
        if not ok:
            return out, i, False
        i = _skip_ws(t, i)
        if i >= n or t[i] != ":":
            return out, i, False
        val, i, ok = _scan_value(t, i + 1, depth + 1)
        if val is not _MISSING:
            out[key] = val
        if not ok:
            return out, i, False


def iter_json_objects(text: str, *, min_keys: int = 1
                      ) -> Iterator[Tuple[int, Dict[str, Any], bool]]:
    """Yield ``(offset, object, complete)`` for each JSON object found.

    Scanning continues *after* a successfully consumed object, so nested
    objects are not re-reported and the second blob on a
    ``request: {...} response: {...}`` line is found on the same pass.
    A `{` that does not open an object (log prose, a C++ scope in a
    message) yields fewer than `min_keys` keys and is skipped.
    """
    i = 0
    n = len(text)
    while i < n:
        start = text.find("{", i)
        if start < 0:
            return
        obj, end, complete = _scan_object(text, start, 0)
        if len(obj) >= min_keys:
            yield start, obj, complete
            i = max(end, start + 1)
        else:
            i = start + 1


def flatten_json(obj: Mapping[str, Any], prefix: str = "",
                 out: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Flatten to dotted paths; scalar arrays are kept as lists.

    ``destPorts: [443]`` stays a list because the list *is* the value a
    reader wants; ``[{...}, {...}]`` becomes ``key[0].sub`` paths because
    otherwise the sub-fields are invisible to a key lookup.
    """
    if out is None:
        out = {}
    for key, val in obj.items():
        path = f"{prefix}{key}"
        if isinstance(val, dict):
            flatten_json(val, path + ".", out)
        elif isinstance(val, list) and any(
                isinstance(v, (dict, list)) for v in val):
            for idx, item in enumerate(val):
                if isinstance(item, dict):
                    flatten_json(item, f"{path}[{idx}].", out)
                else:
                    out[f"{path}[{idx}]"] = item
        else:
            out[path] = val
    return out


@dataclass(frozen=True)
class JsonHarvest:
    """Everything the JSON scanner found in one piece of text."""

    fields: Mapping[str, Any]
    #: One flattened dict per object found, in text order.
    objects: Tuple[Mapping[str, Any], ...] = ()
    #: Keys that appeared in more than one object with differing values.
    #: `fields` keeps the first; this records that a second existed.
    collisions: Mapping[str, Tuple[Any, ...]] = _dc_field(
        default_factory=lambda: MappingProxyType({}))
    objects_found: int = 0
    objects_truncated: int = 0

    def __bool__(self) -> bool:
        return bool(self.fields)


def harvest_json(text: str) -> JsonHarvest:
    """Harvest every embedded JSON object, tolerating truncation."""
    merged: Dict[str, Any] = {}
    per_object: List[Mapping[str, Any]] = []
    collisions: Dict[str, List[Any]] = {}
    truncated = 0
    for _off, obj, complete in iter_json_objects(text):
        flat = flatten_json(obj)
        per_object.append(MappingProxyType(dict(flat)))
        if not complete:
            truncated += 1
        for key, val in flat.items():
            if key in merged:
                if merged[key] != val:
                    collisions.setdefault(key, [merged[key]]).append(val)
                continue
            merged[key] = val
    return JsonHarvest(
        fields=MappingProxyType(merged),
        objects=tuple(per_object),
        collisions=MappingProxyType(
            {k: tuple(v) for k, v in collisions.items()}),
        objects_found=len(per_object),
        objects_truncated=truncated,
    )


_RE_JSON_FRAGMENT = re.compile(
    r'"(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)"\s*:\s*'
    r'(?P<val>"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)'
)


def harvest_json_fragments(text: str) -> Dict[str, Any]:
    """Scalar ``"key": value`` pairs, with no structure required.

    For text that is a *middle* of an object — a continuation block read
    on its own, where the opening `{` is on a line you do not have.
    Arrays and nested objects are skipped because without the opening
    brace their extent is unknowable. Prefer `harvest_json` on
    ``store.record_text(line)``, which has the whole record.
    """
    out: Dict[str, Any] = {}
    for mo in _RE_JSON_FRAGMENT.finditer(text):
        raw = mo.group("val")
        if raw[0] == '"':
            val: Any = raw[1:-1]
        elif raw in ("true", "false"):
            val = raw == "true"
        elif raw == "null":
            val = None
        else:
            val = float(raw) if "." in raw else int(raw)
        out.setdefault(mo.group("key"), val)
    return out


# =====================================================================
# 4. SCHEMA REGISTRY
# =====================================================================
# A record type is data: an anchor that says "this text is one of these",
# the labels/keys it is known to carry, and optional coercions. Adding
# the next structured record should mean adding a `RecordSchema`, not
# writing another parser.

Coercion = Callable[[str], Any]


@dataclass(frozen=True)
class RecordMatch:
    """One record parsed against one schema."""

    schema: str
    fields: Mapping[str, Any]
    #: Declared labels/keys the text did not carry.
    declared_missing: Tuple[str, ...] = ()
    #: Fields present that the schema does not declare. Not an error —
    #: this is how a platform difference announces itself (macOS adds
    #: destPort / destinationIp to the tunnel-api blob).
    undeclared: Tuple[str, ...] = ()
    #: Labels found are a strict prefix of the declared order.
    stops_short: bool = False
    #: JSON object closed / label row carried every declared label.
    complete: bool = True
    #: (field, value) pairs whose value is outside the schema's observed
    #: set. Reported, never corrected — this is what a mid-value
    #: truncation looks like ("ACTION: Bypa").
    unexpected_values: Tuple[Tuple[str, Any], ...] = ()
    #: Fields whose coercion raised. Raw string is kept in `fields`.
    coerce_failed: Tuple[str, ...] = ()
    #: Physical line offset within the text that was parsed, so a caller
    #: can point at the row inside a multi-row continuation block.
    line_offset: int = 0

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


@dataclass(frozen=True)
class RecordSchema:
    """Declarative description of one structured record type."""

    name: str
    #: Text is this record type iff `anchor` matches it.
    anchor: Pattern[str]
    #: "labelled" (Label: value columns) | "json" | "kv".
    kind: str = "labelled"
    labels: Tuple[str, ...] = ()
    json_keys: Tuple[str, ...] = ()
    kv_keys: Tuple[str, ...] = ()
    #: Named groups of `anchor` to lift into the field dict (the row
    #: index in `[   7] IP: ...` is in the anchor, not in a label).
    anchor_groups: Tuple[str, ...] = ()
    coerce: Mapping[str, Coercion] = _dc_field(
        default_factory=lambda: MappingProxyType({}))
    known_values: Mapping[str, FrozenSet[str]] = _dc_field(
        default_factory=lambda: MappingProxyType({}))
    separator: str = ":"
    #: True when each physical line is its own record (a table).
    per_line: bool = True
    note: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("labelled", "json", "kv"):
            raise ValueError(f"unknown schema kind: {self.kind!r}")
        if self.kind == "labelled" and not self.labels:
            raise ValueError(f"{self.name}: labelled schema needs labels")
        object.__setattr__(
            self, "_labelset",
            LabelSet(self.labels, separator=self.separator)
            if self.kind == "labelled" else None,
        )

    # -- declared field names, whatever the kind
    @property
    def declared(self) -> Tuple[str, ...]:
        if self.kind == "labelled":
            return self.labels
        if self.kind == "json":
            return self.json_keys
        return self.kv_keys

    def matches(self, text: str) -> bool:
        return self.anchor.search(text) is not None

    def parse(self, text: str) -> Optional[RecordMatch]:
        """Parse `text` as one record. None if the anchor does not match."""
        mo = self.anchor.search(text)
        if not mo:
            return None
        fields: Dict[str, Any] = {}
        for grp in self.anchor_groups:
            # `re` raises IndexError for a group the anchor does not
            # define — a schema authoring mistake, not a log condition,
            # so it is skipped rather than allowed to kill the parse of
            # every other field on the line.
            try:
                fields[grp] = mo.group(grp)
            except IndexError:
                continue
        missing: Tuple[str, ...] = ()
        stops_short = False
        complete = True
        if self.kind == "labelled":
            parsed = self._labelset.parse(text, declared=self.labels)
            fields.update(parsed.values)
            missing, stops_short = parsed.missing, parsed.stops_short
            complete = not missing
        elif self.kind == "json":
            harvest = harvest_json(text)
            fields.update(harvest.fields)
            missing = tuple(k for k in self.json_keys if k not in fields)
            complete = harvest.objects_truncated == 0
        else:
            fields.update(harvest_kv(text))
            missing = tuple(k for k in self.kv_keys if k not in fields)
            complete = not missing
        coerce_failed: List[str] = []
        for key, fn in self.coerce.items():
            if key in fields:
                try:
                    fields[key] = fn(fields[key])
                except Exception:                       # noqa: BLE001
                    # Coercion never removes evidence: the raw string
                    # stays in `fields` and the failure is reported.
                    coerce_failed.append(key)
        unexpected = tuple(
            (k, fields[k]) for k, allowed in self.known_values.items()
            if k in fields and fields[k] not in allowed
        )
        declared = set(self.declared) | set(self.anchor_groups)
        undeclared = tuple(sorted(k for k in fields if k not in declared))
        return RecordMatch(
            schema=self.name, fields=MappingProxyType(fields),
            declared_missing=missing, undeclared=undeclared,
            stops_short=stops_short, complete=complete,
            unexpected_values=unexpected,
            coerce_failed=tuple(coerce_failed),
        )

    def parse_all(self, text: str) -> List[RecordMatch]:
        """Every record of this type in `text`.

        With `per_line` (a table) each physical line is tried on its own,
        which is what keeps a 6,166-row filter dump from collapsing into
        one record. Filter tables arrive as continuation blocks, so the
        caller normally passes ``store.record_text(line)``.
        """
        if not self.per_line:
            one = self.parse(text)
            return [one] if one else []
        out: List[RecordMatch] = []
        for offset, raw in enumerate(text.split("\n")):
            line = raw.rstrip("\r")
            match = self.parse(line)
            if match is not None:
                out.append(RecordMatch(
                    schema=match.schema, fields=match.fields,
                    declared_missing=match.declared_missing,
                    undeclared=match.undeclared,
                    stops_short=match.stops_short, complete=match.complete,
                    unexpected_values=match.unexpected_values,
                    coerce_failed=match.coerce_failed,
                    line_offset=offset,
                ))
        return out


_REGISTRY: Dict[str, RecordSchema] = {}


def register(schema: RecordSchema, *, replace: bool = False) -> RecordSchema:
    """Add a schema to the registry. Duplicate names are rejected.

    Silently replacing a registered name would make two extractors
    disagree about what a record type means depending on import order.
    """
    if schema.name in _REGISTRY and not replace:
        raise ValueError(f"schema already registered: {schema.name}")
    _REGISTRY[schema.name] = schema
    return schema


def get_schema(name: str) -> RecordSchema:
    return _REGISTRY[name]


def schema_names() -> Tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def match_schemas(text: str, *, names: Optional[Iterable[str]] = None
                  ) -> List[RecordMatch]:
    """Every registered schema that matches `text`, parsed.

    A record can legitimately match more than one schema, so this
    returns a list rather than picking a winner — picking one would be
    an inference.
    """
    wanted = _REGISTRY if names is None else {
        n: _REGISTRY[n] for n in names if n in _REGISTRY}
    out: List[RecordMatch] = []
    for _name, schema in sorted(wanted.items()):
        out.extend(schema.parse_all(text))
    return out


# ---------------------------------------------------------------------
# 4a. Registered schema: the 10-column forwarding-filter table
# ---------------------------------------------------------------------
# Same rows `learned.parse_route_row` was verified on (142,675 rows / 14
# bundles / 96.6% parsed), re-expressed as schema data on top of the
# generic engine. The row index lives in the anchor; the other ten
# fields are labels.

_RE_FILTER_ROW = re.compile(r"^\[\s*(?P<idx>\d+)\]\s+IP:")

_FILTER_LABELS = ("IP", "Mask", "Adapter", "Type", "SRC_PORT", "DST_PORT",
                  "Protocol", "ACTION", "IP_PROTO", "Direction")
try:
    # `learned.ROUTE_ROW_LABELS` is the single source of truth when this
    # module is imported as part of the package; the literal above is
    # the same tuple, kept so the engine still imports (and is testable)
    # standalone, where only a cut-down `learned` exists.
    from .protocol_grammar import ROUTE_ROW_LABELS as _FILTER_LABELS  # type: ignore
except ImportError:
    pass


def _port_range(value: str) -> Tuple[int, int]:
    """``"9000 - 9000"`` -> ``(9000, 9000)``; raises if it is not one."""
    lo, _, hi = value.partition("-")
    return int(lo.strip()), int(hi.strip())


FILTER_ROW = register(RecordSchema(
    name="forwarding_filter_row",
    anchor=_RE_FILTER_ROW,
    kind="labelled",
    labels=tuple(_FILTER_LABELS),
    anchor_groups=("idx",),
    coerce=MappingProxyType({
        "idx": int, "SRC_PORT": _port_range, "DST_PORT": _port_range,
    }),
    known_values=MappingProxyType({
        # Corpus-observed enumerations. A value outside these is a
        # truncated row, and is reported as such rather than dropped.
        "Type": frozenset({
            "ZIA Include/Exclude", "Global Bypass", "ZPA App", "Internal",
            "Drop Inbound Filter", "Default Inbound", "Default Bypass",
            "ZIA SME Inclusions", "Drop Filter"}),
        "ACTION": frozenset({"Bypass", "Redirect", "Drop"}),
        "IP_PROTO": frozenset({"IPv4", "IPv6"}),
        "Direction": frozenset({"Inbound", "Outbound"}),
    }),
    per_line=True,
    note="ZCC traffic-forwarding filter table; emitted as a continuation "
         "block under the preceding timestamped line. Measured on 5 "
         "bundles: 36,137/36,137 rows parsed, 33,750 (93.4%) with all "
         "ten labels, 576 rows ending in a value outside the enums "
         "above. 100% of rows were inside continuation text — reading "
         "line.body alone finds none of them.",
))


# ---------------------------------------------------------------------
# 4b. Registered schema: the tunnel/broker JSON status blob
# ---------------------------------------------------------------------
# `Tunnel api request: {...} response: { ... }`. The response object is
# pretty-printed, so it opens on the body line and closes 2-6
# continuation lines later. Measured on bundle 05: brokerIp/brokerName/
# brokerType/bypassReason land on the body line and dnsTime/nwType/
# pacParseTime/requestType/smeIp/smePort/destinationIps land in the
# continuation — the split is structural (ZCC breaks the line at the
# first array), not random.
#
# The key set is NOT fixed, so undeclared keys are reported rather than
# forced into the schema. Measured on the macOS bundle (20): 4,574
# records carry `destPort` and `destinationIp` which no Windows bundle
# emitted, and `nwType` is absent from all 5,059 of its records while
# Windows bundle 12 has it on 3,673 of 3,673. `sslVpnIp` is undeclared
# on both platforms (3,670 macOS / 1,805 + 2,580 + 2,495 Windows), i.e.
# a genuinely optional field rather than a platform marker.

TUNNEL_API_STATUS = register(RecordSchema(
    name="tunnel_api_status",
    # Two carriers, same object. Measured on bundle 05: 14 records say
    # `Tunnel api request:` and 14 more say `ZSD: Service Discovery
    # Response :` — anchoring on the first alone found exactly half the
    # blobs in the bundle.
    anchor=re.compile(
        r"(?:Tunnel api request|ZSD: Service Discovery Response)\s*:\s*\{"),
    kind="json",
    json_keys=("brokerIp", "brokerName", "brokerType", "bypassReason",
               "destPorts", "destinationIps", "dnsTime", "nwType",
               "pacParseTime", "requestType", "resolvedIp", "smeIp",
               "smePort", "systemProxy", "systemProxyHost",
               "systemProxyPort", "url", "host", "port", "protocol",
               "bypassRequest", "ignoreSystemProxy", "lite"),
    per_line=False,
    note="Per-request forwarding decision. Request and response objects "
         "are both harvested; keys were disjoint in all 5 bundles "
         "measured (zero collisions), so the merged view is "
         "unambiguous. Records with no request object (the ZSD form) "
         "report url/host/port/... through declared_missing rather "
         "than pretending they were absent from the response.",
))

TUNNEL_STATE_JSON = register(RecordSchema(
    name="tunnel_state_json",
    # The `:\s*\{` tail is load-bearing. Without it the anchor also
    # matched `In processGetTunnelStateAndVersion, statusJson set`,
    # which carries no JSON of its own; on bundle 02 that pulled in 2
    # records whose only object was the tray's `Tunnel Status` /
    # `Total Bytes Sent` table — a different record wearing this
    # schema's name.
    anchor=re.compile(
        r"(?:statusJson stringify|Sending tunnelState):\s*\{"),
    kind="json",
    json_keys=("lastLocationSourceUsed", "lwfDriverRunning",
               "stepUpVerifyState", "tapDriverRunning", "tunnelVersion",
               "ziaTunnelState", "zpaAuthState", "zpaTunnelState"),
    per_line=False,
    note="Tray-facing tunnel state snapshot. Carries zpaAuthState, one "
         "of the fourteen continuation-carried fields.",
))


# =====================================================================
# 5. STORE CONVENIENCE — every field of a record, with provenance
# =====================================================================


@dataclass(frozen=True)
class RecordFields:
    """Every field found in one record, and where the evidence sat.

    `body_keys` and `continuation_keys` partition `all`: a key is in
    exactly one of them, which is what lets a UI cite "line 6762" for
    one field and "line 6762 +3" for another without the reader having
    to guess.

    One caveat, measured rather than assumed: a key can be body-visible
    and body-EMPTY. ZCC breaks the line at the first array, so
    `destPorts` opens on the body line and every element sits in the
    continuation — 3,263 of 3,263 such records on bundle 02 and 28 of 28
    on bundle 05 have `destPorts == []` in the body and a populated list
    in the record. The key-set split therefore UNDERSTATES what record
    assembly recovers; compare values, not just key presence, if that
    distinction matters to the caller.
    """

    source_file: str
    line_no: int
    kv: Mapping[str, str]
    json: Mapping[str, Any]
    records: Tuple[RecordMatch, ...]
    body_keys: FrozenSet[str]
    continuation_keys: FrozenSet[str]
    has_continuation: bool = False
    json_truncated: int = 0

    @property
    def all(self) -> Dict[str, Any]:
        """kv + json merged; JSON wins a collision.

        JSON wins because a `key=value` hit inside a JSON blob is the
        same evidence seen through a blunter lens, and the JSON scanner
        typed it (int / bool / list) while the kv harvester did not.
        """
        merged: Dict[str, Any] = dict(self.kv)
        merged.update(self.json)
        return merged

    def origin(self, key: str) -> Optional[str]:
        """"body" | "continuation" | None (key not in this record)."""
        if key in self.body_keys:
            return "body"
        if key in self.continuation_keys:
            return "continuation"
        return None

    def provenance(self, key: str) -> Optional[Tuple[str, int, str]]:
        """``(source_file, line_no, "body"|"continuation")`` or None."""
        where = self.origin(key)
        if where is None:
            return None
        return (self.source_file, self.line_no, where)


def fields_for_line(store: Any, line: Any, *,
                    schemas: Optional[Iterable[str]] = None) -> RecordFields:
    """Every field in `line`'s whole record, with provenance.

    `store` is duck-typed on `record_text(line)` (slice 13) so this works
    with `LogStore` and with any test double. The body is harvested a
    second time on its own for one reason: subtracting its key set from
    the record's is the only honest way to say "this field exists ONLY
    because continuation text was assembled" — which is the entire point
    of record assembly.
    """
    body = getattr(line, "body", "") or ""
    record = store.record_text(line) if store is not None else body

    body_kv = harvest_kv(body)
    body_json = harvest_json(body)
    body_keys = frozenset(body_kv) | frozenset(body_json.fields)

    rec_kv = harvest_kv(record)
    rec_json = harvest_json(record)
    all_keys = frozenset(rec_kv) | frozenset(rec_json.fields)

    return RecordFields(
        source_file=getattr(line, "source_file", "") or "",
        line_no=getattr(line, "line_no", -1),
        kv=MappingProxyType(rec_kv),
        json=MappingProxyType(dict(rec_json.fields)),
        records=tuple(match_schemas(record, names=schemas)),
        body_keys=body_keys & all_keys,
        continuation_keys=all_keys - body_keys,
        has_continuation=len(record) > len(body),
        json_truncated=rec_json.objects_truncated,
    )
