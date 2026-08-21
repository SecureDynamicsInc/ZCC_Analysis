# Copyright 2026 SecureDynamics, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Recover the PAC documents a ZCC bundle carries.

A proxy auto-config file decides, per host, whether traffic is handed to
a Zscaler service edge or sent DIRECT. That makes it first-order evidence
for "this site is not going through the tunnel" and for the bypass
misconfiguration family already covered by ``sops/bypass_misconfiguration.md``
— but the bundle never presents it as a file. It shows up two ways:

  * as a standalone ``*.pac`` / ``*.js`` artefact, when the deployment
    ships a file-based PAC, and
  * inline in a tunnel/UPM log, because ZCC writes the PAC body it just
    downloaded or reloaded into its own log.

This module recovers both and hands the UI the source text unmodified,
so an engineer reads the customer's actual PAC rather than a paraphrase.

Deliberate constraints:

``function FindProxyForURL`` is the only anchor.
    That signature *is* the definition of a PAC, so anchoring on it
    avoids inventing PAC evidence from ordinary log prose that merely
    mentions the word "PAC" (``ZUpmPacDownloader``, "PAC fetch
    successful", and friends appear constantly).

The scan is bounded.
    A measured bundle reaches 21,947 rotations. Files are streamed in
    chunks, only a window around each anchor is materialised, plain logs
    are read before rotation contents, and file/byte/document caps stop
    the walk. :class:`PacScan` reports what was covered so a clean result
    is distinguishable from an incomplete one.

Identical PAC bodies collapse to one document.
    A PAC re-downloaded every hour across 40 rotations is one document
    with an occurrence count, not 40 findings.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Sequence, Tuple

# The PAC entry point, matched case-insensitively on bytes. ``FindProxyForURLEx``
# (the IPv6 variant) shares this prefix and is picked up by the same anchor.
_ANCHOR = b"findproxyforurl"

# The anchor alone is not enough: ZCC logs sentences that merely name the
# function ("checking FindProxyForURL availability"). A recovered region only
# counts as a PAC once it holds the actual definition — signature plus the
# brace that opens the body.
_PAC_DEFINITION = re.compile(
    r"function\s+FindProxyForURL\w*\s*\([^)]*\)\s*\{", re.IGNORECASE
)

# Shortest plausible PAC body; anything smaller is a fragment, not evidence.
_MIN_PAC_CHARS = 40

# Same record-start shape ``log_parser`` uses as its fast pre-filter. A line
# that starts like this is a new log record, which is what ends an inline PAC.
_TS_START = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.")

# Full preamble: timestamp, optional (tz), optional [pid:tid], optional level.
# Stripped from PAC lines when ZCC logged the PAC one prefixed line at a time.
# The trailing ``[ \t]`` consumes exactly the one delimiter space the logger
# writes before its message — anything past that is the PAC's own indentation
# and has to survive, or the displayed source loses its structure.
_LOG_PREAMBLE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+"
    r"(?:\([+-]\d{2}:?\d{2}\))?"
    r"(?:\[\d+:\d+\])?"
    r"(?:[ \t]+\[?(?:INF|DBG|ERR|WRN|TRC|VRB|FTL|info|debug|error|warn|warning"
    r"|trace|verbose|fatal)\]?)?"
    r"(?:[ \t]+\[[^\]]{1,40}\])?"
    r"[ \t]"
)

# Only text-shaped members are opened at all, which keeps the scanner away
# from the ``.pcapng``, ``.mmdb``, and ``.db`` members a bundle also holds.
_TEXT_SUFFIXES = frozenset({
    ".log", ".txt", ".pac", ".js", ".dat", ".conf", ".cfg", ".ini",
    ".json", ".xml", ".old",
})
_PAC_FILE_SUFFIXES = frozenset({".pac", ".js"})

# A rotation keeps its component suffix and adds an index (``ZSATunnel.log.1``),
# so eligibility looks at every suffix — but the *last* one still decides,
# because ``ZSATunnel.log.zip`` is compressed bytes, not text. The extracted
# contents of that archive are reached through their own directory instead.
_BINARY_LAST_SUFFIXES = frozenset({
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".cab", ".tar",
    ".pcap", ".pcapng", ".mmdb", ".db", ".sqlite", ".etl", ".evtx",
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".exe", ".dll", ".sys", ".bin",
})

# Components that actually write a PAC body are read first.
_PRIORITY_TOKENS = (
    "zsatunnel", "zsaupm", "upm", "zsaservice", "zsatray", "zsawinproxy",
    "zscaler", "pac",
)

CHUNK_BYTES = 1 << 20            # streaming read size while hunting the anchor
WINDOW_BYTES = 512 * 1024        # most a single carved PAC may span
LOOKBACK_CHARS = 240             # how far back to find the `function` keyword
MAX_FILES = 4_000
MAX_BYTES = 512 * 1024 * 1024
MAX_DOCUMENTS = 24
MAX_WHOLE_FILE_BYTES = 4 * 1024 * 1024
MAX_ANCHORS_PER_FILE = 40

# How many of ZCC's own log records may appear inside an unclosed PAC body
# before the carve gives up and reports the result as truncated.
_MAX_INTERLEAVED_RECORDS = 200


# --------------------------------------------------------------------------
# Result types
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class PacDocument:
    """One distinct PAC body, with where it was found.

    ``text`` is the recovered source. It is de-prefixed when ZCC logged the
    PAC with a log preamble on every line, and JSON-unescaped when the PAC
    was embedded in a config value, but is otherwise byte-for-byte what the
    bundle contained — the view is meant to be read as-is.
    """

    text: str
    fingerprint: str
    source_file: str
    line_no: int
    occurrences: int = 1
    sources: Tuple[str, ...] = ()
    truncated: bool = False
    log_embedded: bool = False
    standalone_file: bool = False
    preamble_stripped: bool = False
    json_unescaped: bool = False
    context: str = ""
    raw_excerpt: str = ""
    # The recovered body before writer-inserted blank lines were collapsed.
    # Kept so the view can show either the restored spacing or exactly what
    # the bundle held, and so the two are never confused for each other.
    as_found_text: str = ""
    blank_lines_collapsed: int = 0

    @property
    def spacing_restored(self) -> bool:
        return self.blank_lines_collapsed > 0

    @property
    def as_found(self) -> str:
        return self.as_found_text or self.text

    @property
    def line_count(self) -> int:
        return len(self.text.splitlines())

    @property
    def byte_size(self) -> int:
        return len(self.text.encode("utf-8", errors="replace"))

    @property
    def origin(self) -> str:
        if self.standalone_file:
            return "Standalone PAC file"
        if self.log_embedded:
            return "Inline in log"
        return "Recovered from bundle"


@dataclass
class PacScan:
    """Everything the PAC pass found, plus honest coverage."""

    documents: List[PacDocument] = field(default_factory=list)
    files_scanned: int = 0
    files_eligible: int = 0
    bytes_scanned: int = 0
    unreadable: List[str] = field(default_factory=list)
    hit_file_cap: bool = False
    hit_byte_cap: bool = False
    hit_document_cap: bool = False

    @property
    def found(self) -> int:
        return len(self.documents)

    @property
    def total_occurrences(self) -> int:
        return sum(doc.occurrences for doc in self.documents)

    @property
    def complete(self) -> bool:
        """True when the walk finished without tripping a cap."""
        return not (self.hit_file_cap or self.hit_byte_cap or self.hit_document_cap)


# --------------------------------------------------------------------------
# Brace tracking
#
# Used only to find where a PAC ends when every line carries a log preamble
# (there is no "next log record" line to stop at in that layout). Strings and
# comments are skipped; a brace inside a regex quantifier such as ``{2,3}``
# would still be counted, which is why an unbalanced carve is reported as
# ``truncated`` rather than silently trimmed.
# --------------------------------------------------------------------------

@dataclass
class _BraceState:
    depth: int = 0
    opened: bool = False
    in_block_comment: bool = False

    @property
    def balanced(self) -> bool:
        return self.opened and self.depth <= 0


def _feed_braces(state: _BraceState, line: str) -> _BraceState:
    quote = ""
    index = 0
    length = len(line)
    while index < length:
        char = line[index]
        if state.in_block_comment:
            if char == "*" and index + 1 < length and line[index + 1] == "/":
                state.in_block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            index += 1
            continue
        if char == "/" and index + 1 < length:
            following = line[index + 1]
            if following == "/":
                break                      # line comment: nothing else counts
            if following == "*":
                state.in_block_comment = True
                index += 2
                continue
        if char == "{":
            state.depth += 1
            state.opened = True
        elif char == "}":
            state.depth -= 1
        index += 1
    return state


# --------------------------------------------------------------------------
# Carving
# --------------------------------------------------------------------------

def collapse_doubled_blank_lines(text: str) -> Tuple[str, int]:
    """Undo a writer that emitted one extra line break per line.

    When a component writes a multi-line blob out line by line, each write can
    carry the blob's own trailing newline *and* the writer's, so the copy that
    lands on disk has a blank line after every line of the original. The
    signature is an alternating pattern: nearly every content line is followed
    by exactly one blank.

    Removing one blank from every run restores the original spacing —
    a single blank disappears, a pair becomes one — which is why the transform
    is expressed that way rather than as "collapse runs to one". A file with
    genuine paragraph spacing is left alone, because its blanks do not follow
    nearly every line.

    Returns the text and how many blank lines were removed, so the UI can say
    what it did instead of quietly reflowing the source.
    """
    lines = text.split("\n")
    content = [index for index, line in enumerate(lines) if line.strip()]
    if len(content) < 6:
        return text, 0

    # How many content lines are immediately followed by a blank? The final
    # content line is excluded from the denominator: the closing brace ends the
    # file and is never followed by anything, so counting it would make short
    # PACs fail the test for a reason that has nothing to do with the writer.
    considered = content[:-1]
    followed = sum(
        1 for index in considered
        if index + 1 < len(lines) and not lines[index + 1].strip()
    )
    if not considered or followed < len(considered) * 0.7:
        return text, 0

    out: List[str] = []
    removed = 0
    index = 0
    total = len(lines)
    while index < total:
        line = lines[index]
        if line.strip():
            out.append(line)
            index += 1
            continue
        run = 0
        while index < total and not lines[index].strip():
            run += 1
            index += 1
        # One break per run belonged to the writer, not the file.
        out.extend([""] * (run - 1))
        removed += 1
    return "\n".join(out), removed


def _looks_pac_continuation(line: str) -> bool:
    """A top-level PAC/JS construct that may follow ``FindProxyForURL``."""
    stripped = line.strip()
    if not stripped:
        return True
    return stripped.startswith(("function", "var ", "let ", "const ", "/*", "//", "}"))


def _unescape_json_embedded(text: str) -> Tuple[str, bool]:
    r"""Turn a PAC stored as a JSON/plist string value back into source.

    ZCC configuration payloads carry the PAC as one escaped line. Detect that
    by the absence of real newlines alongside several ``\n`` escapes.
    """
    if text.count("\\n") < 3 or text.count("\n") > 1:
        return text, False
    restored = (
        text.replace("\\r\\n", "\n")
            .replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace('\\"', '"')
            .replace("\\/", "/")
            .replace("\\\\", "\\")
    )
    return restored, True


def normalize_newlines(text: str) -> str:
    r"""Collapse every line-ending convention to a single ``\n``.

    Applied before anything splits the text, because splitting first turns an
    unusual ending into extra blank lines: ``str.splitlines`` treats a lone
    ``\r`` as its own break, so ``line\n\rline`` becomes three lines and the
    displayed PAC gains a blank row between every real one. CRLF, LFCR, and
    bare CR all mean one line break here.
    """
    return text.replace("\r\n", "\n").replace("\n\r", "\n").replace("\r", "\n")


def _string_literal_end(text: str, quote: str) -> int:
    """Offset of the unescaped ``quote`` that closes a string literal."""
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index
        index += 1
    return -1


@dataclass(frozen=True)
class _Carved:
    text: str
    truncated: bool
    log_embedded: bool
    preamble_stripped: bool
    json_unescaped: bool
    context: str


def _carve_region(window: str, anchor_at: int) -> _Carved:
    """Extract the PAC starting at/near ``anchor_at`` inside ``window``."""
    # Normalise before any split, and keep the anchor offset valid by doing it
    # on both halves independently — a CRLF collapsed ahead of the anchor would
    # otherwise shift it.
    head = normalize_newlines(window[:anchor_at])
    window = head + normalize_newlines(window[anchor_at:])
    anchor_at = len(head)
    prefix = window[:anchor_at]
    lowered_prefix = prefix.lower()
    keyword_at = lowered_prefix.rfind("function")
    start = keyword_at if keyword_at >= 0 and anchor_at - keyword_at <= LOOKBACK_CHARS else anchor_at

    # Provenance: the last thing the log said before the PAC body began.
    context = ""
    for candidate in reversed(prefix[:start].splitlines()):
        if candidate.strip():
            context = candidate.strip()[:240]
            break

    # A PAC handed over as a JSON/plist string value has an exact end: the
    # quote that closes the literal. Cutting there keeps the surrounding
    # config payload out of the displayed source.
    leading = prefix[:start].rstrip()
    if leading.endswith(('"', "'")):
        quote = leading[-1]
        body = window[start:]
        end = _string_literal_end(body, quote)
        literal = body[:end] if end >= 0 else body
        text, unescaped = _unescape_json_embedded(literal)
        if unescaped:
            return _Carved(
                text=text.rstrip(),
                truncated=end < 0,
                log_embedded=True,
                preamble_stripped=False,
                json_unescaped=True,
                context=context,
            )

    lines = window[start:].split("\n")
    if not lines:
        return _Carved("", True, False, False, False, context)

    sample = [line for line in lines[:12] if line.strip()]
    prefixed = bool(sample) and sum(
        1 for line in sample if _TS_START.match(line)
    ) >= max(2, int(len(sample) * 0.6))

    # A PAC that keeps its own line breaks inside a log ends where the next
    # log record begins. The first line is skipped because the record that
    # introduced the PAC usually carries the opening ``function`` itself.
    log_embedded = bool(context) or prefixed

    kept: List[str] = []
    state = _BraceState()
    truncated = True

    if prefixed:
        for line in lines:
            body = _LOG_PREAMBLE.sub("", line, count=1) if _TS_START.match(line) else line
            if state.balanced and not _looks_pac_continuation(body):
                truncated = False
                break
            kept.append(body)
            _feed_braces(state, body)
        else:
            truncated = not state.balanced
    else:
        # A log record ends the PAC only once the body has closed. ZCC can
        # interleave its own records into a PAC it is writing out, and stopping
        # at the first one cut the source off mid-file — the closing brace is
        # the end, not the next timestamp.
        skipped = 0
        for position, line in enumerate(lines):
            if position and _TS_START.match(line):
                if state.balanced:
                    truncated = False
                    break
                skipped += 1
                if skipped > _MAX_INTERLEAVED_RECORDS:
                    break
                continue
            kept.append(line)
            _feed_braces(state, line)
        else:
            # Window ended without a following log record. A balanced body
            # means we still saw the whole PAC.
            truncated = not state.balanced

    text = "\n".join(line.rstrip("\r") for line in kept).rstrip()
    text, unescaped = _unescape_json_embedded(text)
    if unescaped:
        log_embedded = True
        truncated = False
    return _Carved(
        text=text,
        truncated=truncated,
        log_embedded=log_embedded,
        preamble_stripped=prefixed,
        json_unescaped=unescaped,
        context=context,
    )


# --------------------------------------------------------------------------
# File walk
# --------------------------------------------------------------------------

def _name_rank(path: Path) -> int:
    lowered = path.name.lower()
    for position, token in enumerate(_PRIORITY_TOKENS):
        if token in lowered:
            return position
    return len(_PRIORITY_TOKENS)


def _candidate_files(root: Path) -> List[Path]:
    """Eligible files, most likely to hold a PAC first.

    Standalone PAC artefacts lead, then plain logs, then the contents of
    extracted rotations — so a capped scan spends its budget on current
    evidence rather than on year-old rotations.
    """
    pac_files: List[Path] = []
    plain: List[Path] = []
    rotations: List[Path] = []
    for path in Path(root).rglob("*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        suffixes = [item.lower() for item in path.suffixes[-3:]]
        suffix = suffixes[-1] if suffixes else ""
        if suffix in _BINARY_LAST_SUFFIXES:
            continue
        if not any(item in _TEXT_SUFFIXES for item in suffixes):
            continue
        if suffix in _PAC_FILE_SUFFIXES:
            pac_files.append(path)
        elif any(part.endswith("_extracted") for part in path.parts):
            rotations.append(path)
        else:
            plain.append(path)
    for group in (pac_files, plain, rotations):
        group.sort(key=lambda item: (_name_rank(item), str(item)))
    return pac_files + plain + rotations


def _iter_anchors(handle, limit: int) -> Iterator[Tuple[int, int]]:
    """Yield ``(byte_offset, line_no)`` for each PAC anchor in the stream.

    Exactly ``len(_ANCHOR) - 1`` bytes are carried between chunks: enough to
    catch an anchor split across a boundary, too few to hold a whole anchor,
    so no hit is reported twice.
    """
    carry = b""
    base = 0
    lines_before = 0
    consumed = 0
    overlap = len(_ANCHOR) - 1
    while consumed < limit:
        chunk = handle.read(min(CHUNK_BYTES, limit - consumed))
        if not chunk:
            break
        consumed += len(chunk)
        window = carry + chunk
        lowered = window.lower()
        cursor = 0
        while True:
            found = lowered.find(_ANCHOR, cursor)
            if found < 0:
                break
            yield base + found, lines_before + window.count(b"\n", 0, found) + 1
            cursor = found + 1
        keep = min(overlap, len(window))
        settled = len(window) - keep
        lines_before += window.count(b"\n", 0, settled)
        base += settled
        carry = window[settled:]


def _read_window(path: Path, anchor_offset: int) -> Tuple[str, int, int]:
    """Materialise a bounded window around one anchor.

    Decoding the pre-anchor bytes separately keeps the anchor's character
    offset correct even when the log holds multi-byte UTF-8. The byte count is
    returned so these reads draw on the same budget as the streaming scan.
    """
    back = min(anchor_offset, LOOKBACK_CHARS * 4)
    with path.open("rb") as handle:
        handle.seek(anchor_offset - back)
        blob = handle.read(back + WINDOW_BYTES)
    prefix = blob[:back].decode("utf-8", errors="replace")
    rest = blob[back:].decode("utf-8", errors="replace")
    return prefix + rest, len(prefix), len(blob)


def _whole_file_document(path: Path, root: Path, line_no: int) -> PacDocument | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    text = normalize_newlines(raw.decode("utf-8-sig", errors="replace")).rstrip()
    text, unescaped = _unescape_json_embedded(text)
    if not _is_pac_body(text):
        # A ``.js`` artefact that only mentions the name is not a PAC.
        return None
    display, removed = collapse_doubled_blank_lines(text)
    return PacDocument(
        text=display,
        fingerprint=_fingerprint(display),
        source_file=_relative(path, root),
        line_no=line_no,
        sources=(_relative(path, root),),
        standalone_file=True,
        json_unescaped=unescaped,
        context="",
        raw_excerpt="",
        as_found_text=text,
        blank_lines_collapsed=removed,
    )


def _is_pac_body(text: str) -> bool:
    """True when ``text`` actually defines ``FindProxyForURL``."""
    return len(text) >= _MIN_PAC_CHARS and bool(_PAC_DEFINITION.search(text))


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _fingerprint(text: str) -> str:
    normalized = "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def _merge(documents: Dict[str, PacDocument], candidate: PacDocument) -> None:
    """Collapse an identical PAC body onto the document already recorded."""
    existing = documents.get(candidate.fingerprint)
    if existing is None:
        documents[candidate.fingerprint] = candidate
        return
    sources = tuple(dict.fromkeys(existing.sources + candidate.sources))
    # A standalone file, or a complete carve, is the better copy to display.
    better = candidate if (
        candidate.standalone_file and not existing.standalone_file
    ) or (existing.truncated and not candidate.truncated) else existing
    documents[candidate.fingerprint] = PacDocument(
        text=better.text,
        fingerprint=existing.fingerprint,
        source_file=better.source_file,
        line_no=better.line_no,
        occurrences=existing.occurrences + candidate.occurrences,
        sources=sources,
        truncated=better.truncated,
        log_embedded=existing.log_embedded or candidate.log_embedded,
        standalone_file=existing.standalone_file or candidate.standalone_file,
        preamble_stripped=better.preamble_stripped,
        json_unescaped=better.json_unescaped,
        # A standalone artefact has no provenance line of its own, so keep any
        # log context an inline copy of the same PAC contributed.
        context=better.context or existing.context or candidate.context,
        raw_excerpt=better.raw_excerpt or existing.raw_excerpt or candidate.raw_excerpt,
        as_found_text=better.as_found_text,
        blank_lines_collapsed=better.blank_lines_collapsed,
    )


def scan_bundle(
    root: Path,
    *,
    max_files: int = MAX_FILES,
    max_bytes: int = MAX_BYTES,
    max_documents: int = MAX_DOCUMENTS,
) -> PacScan:
    """Find every distinct PAC document under an extracted bundle root."""
    scan = PacScan()
    root = Path(root)
    candidates = _candidate_files(root)
    scan.files_eligible = len(candidates)
    documents: Dict[str, PacDocument] = {}

    for path in candidates:
        if len(documents) >= max_documents:
            scan.hit_document_cap = True
            break
        if scan.files_scanned >= max_files:
            scan.hit_file_cap = True
            break
        if scan.bytes_scanned >= max_bytes:
            scan.hit_byte_cap = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if not size:
            continue
        budget = min(size, max_bytes - scan.bytes_scanned)
        scan.files_scanned += 1
        try:
            with path.open("rb") as handle:
                anchors = []
                for offset, line_no in _iter_anchors(handle, budget):
                    anchors.append((offset, line_no))
                    if len(anchors) >= MAX_ANCHORS_PER_FILE:
                        break
        except OSError as exc:
            scan.unreadable.append(f"{_relative(path, root)}: {exc}")
            continue
        scan.bytes_scanned += budget
        if not anchors:
            continue

        if path.suffix.lower() in _PAC_FILE_SUFFIXES and size <= MAX_WHOLE_FILE_BYTES:
            # A dedicated PAC artefact is shown whole: no carving needed, and
            # helper functions after the entry point stay attached.
            document = _whole_file_document(path, root, anchors[0][1])
            if document is not None:
                _merge(documents, document)
                continue

        for offset, line_no in anchors:
            if scan.bytes_scanned >= max_bytes:
                # Carve reads draw on the same budget as the streaming scan, so
                # a log that re-downloads its PAC hourly cannot quietly turn
                # into unbounded work.
                scan.hit_byte_cap = True
                break
            try:
                window, anchor_at, consumed = _read_window(path, offset)
            except OSError as exc:
                scan.unreadable.append(f"{_relative(path, root)}: {exc}")
                break
            scan.bytes_scanned += consumed
            carved = _carve_region(window, anchor_at)
            if not _is_pac_body(carved.text):
                # Prose that merely names the function, not a PAC body.
                continue
            display, removed = collapse_doubled_blank_lines(carved.text)
            relative = _relative(path, root)
            _merge(documents, PacDocument(
                text=display,
                fingerprint=_fingerprint(display),
                as_found_text=carved.text,
                blank_lines_collapsed=removed,
                source_file=relative,
                line_no=line_no,
                sources=(relative,),
                truncated=carved.truncated,
                log_embedded=carved.log_embedded,
                preamble_stripped=carved.preamble_stripped,
                json_unescaped=carved.json_unescaped,
                context=carved.context,
                raw_excerpt=window[max(0, anchor_at - 400):anchor_at + 1200],
            ))
            if len(documents) >= max_documents:
                scan.hit_document_cap = True
                break

    scan.documents = sorted(
        documents.values(),
        key=lambda doc: (not doc.standalone_file, -doc.occurrences, doc.source_file),
    )
    return scan


# --------------------------------------------------------------------------
# Read-only description of one PAC, for the header above the source view
# --------------------------------------------------------------------------

_DIRECT_RETURN = re.compile(r"return\s+[\"']DIRECT[\"']", re.IGNORECASE)
_PROXY_RETURN = re.compile(r"return\s+[\"']((?:PROXY|HTTPS?|SOCKS)[^\"']*)[\"']", re.IGNORECASE)
_HOST_MATCH = re.compile(
    r"(?:shExpMatch|localHostOrDomainIs|dnsDomainIs)\s*\(\s*[^,]+,\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_FUNCTIONS = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(")
_SUBNET_MATCH = re.compile(
    r"isInNet\s*\(\s*[^,]+,\s*[\"']([^\"']+)[\"']\s*,\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)

# A gateway placeholder the PAC server has not substituted yet, e.g.
# ``${COUNTRY_GATEWAY_FX}``. Their presence is what separates an authored
# template from the PAC a client was actually served.
_PAC_VARIABLE = re.compile(r"\$\{([^}]+)\}")

# ``PROXY host:port`` / ``HTTPS host:port`` / ``SOCKS host:port`` / ``DIRECT``
_FORWARD_TOKEN = re.compile(
    r"^(?P<kind>PROXY|HTTPS|HTTP|SOCKS5|SOCKS4|SOCKS|DIRECT)"
    r"(?:\s+(?P<target>\S+))?$",
    re.IGNORECASE,
)

# A `/` here opens a regex literal rather than dividing, which matters because
# a character class can legitimately contain `//`.
_REGEX_PRECEDERS = frozenset("=(,:[!&|?{};+-*%~^<>")


def strip_comments(text: str) -> str:
    """Blank out ``//`` and ``/* */`` comments, preserving line structure.

    Necessary because a PAC is a working document: a deployment's history sits
    in it as commented-out bypasses. Counting those as live rules is not a
    cosmetic error — it answers "is this host bypassed?" with a yes when the
    rule is switched off. The measured MSSP template carries 38 commented-out
    host patterns and 2 of its 3 PROXY returns are inactive.

    String and regex literals are skipped so a `//` inside a quoted host or a
    character class is not mistaken for a comment. Comment characters are
    replaced by spaces rather than deleted, so offsets and line numbers still
    line up with the displayed source.
    """
    out: List[str] = []
    index = 0
    length = len(text)
    previous = ""  # last significant code character, for regex detection
    while index < length:
        char = text[index]

        if char in "\"'":
            out.append(char)
            index += 1
            while index < length:
                current = text[index]
                out.append(current)
                if current == "\\" and index + 1 < length:
                    out.append(text[index + 1])
                    index += 2
                    continue
                index += 1
                if current == char or current == "\n":
                    break
            previous = char
            continue

        if char == "/" and index + 1 < length and text[index + 1] == "/":
            while index < length and text[index] != "\n":
                out.append(" ")
                index += 1
            continue

        if char == "/" and index + 1 < length and text[index + 1] == "*":
            while index < length and not (
                text[index] == "*" and index + 1 < length and text[index + 1] == "/"
            ):
                out.append("\n" if text[index] == "\n" else " ")
                index += 1
            for _ in range(2):
                if index < length:
                    out.append(" ")
                    index += 1
            continue

        if char == "/" and (not previous or previous in _REGEX_PRECEDERS):
            out.append(char)
            index += 1
            in_class = False
            while index < length:
                current = text[index]
                out.append(current)
                if current == "\\" and index + 1 < length:
                    out.append(text[index + 1])
                    index += 2
                    continue
                index += 1
                if current == "[":
                    in_class = True
                elif current == "]":
                    in_class = False
                elif current == "\n" or (current == "/" and not in_class):
                    break
            previous = "/"
            continue

        out.append(char)
        if not char.isspace():
            previous = char
        index += 1
    return "".join(out)


def forwarding_targets(returns: Iterable[str]) -> List[Dict[str, object]]:
    """Split PROXY return values into individual forwarding targets.

    A single return carries an ordered failover list, e.g.
    ``PROXY 165.225.60.15:80; PROXY 104.129.198.10:80; DIRECT``. Zscaler's PAC
    server substitutes real Public Service Edge addresses for the
    ``${GATEWAY}`` family when it serves the file, so a PAC recovered from a
    client's logs normally carries literal addresses where the authored
    template carries variables. Both forms are reported.
    """
    targets: List[Dict[str, object]] = []
    seen = set()
    for value in returns:
        for position, chunk in enumerate(str(value).split(";")):
            token = chunk.strip()
            if not token:
                continue
            match = _FORWARD_TOKEN.match(token)
            if not match:
                continue
            kind = match.group("kind").upper()
            target = (match.group("target") or "").strip()
            host, port = target, None
            if target and ":" in target and not target.endswith(":"):
                head, _, tail = target.rpartition(":")
                if tail.isdigit() and head:
                    host, port = head, int(tail)
            variable = bool(_PAC_VARIABLE.search(host))
            key = (kind, host, port)
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "order": position + 1,
                "kind": kind,
                "host": host,
                "port": port,
                "variable": variable,
            })
    return targets


def describe(document: PacDocument) -> Dict[str, object]:
    """Counts and named hosts read straight out of the PAC text.

    Only *live* code is counted; commented-out rules are reported separately
    rather than mixed in. This is description, not judgement: it reports what
    the file does and does not currently do, and draws no conclusion about
    whether a given bypass is correct for the tenant.
    """
    text = document.text
    live = strip_comments(text)

    live_proxy = [match.group(1).strip() for match in _PROXY_RETURN.finditer(live)]
    all_proxy = [match.group(1).strip() for match in _PROXY_RETURN.finditer(text)]
    live_hosts = tuple(dict.fromkeys(_HOST_MATCH.findall(live)))
    all_hosts = tuple(dict.fromkeys(_HOST_MATCH.findall(text)))
    live_host_set = set(live_hosts)
    live_proxy_set = set(live_proxy)
    live_subnets = tuple(dict.fromkeys(
        f"{network}/{mask}" for network, mask in _SUBNET_MATCH.findall(live)
    ))

    targets = forwarding_targets(live_proxy)
    unresolved = tuple(dict.fromkeys(
        name for target in targets
        for name in _PAC_VARIABLE.findall(str(target["host"]))
    ))

    return {
        "functions": tuple(dict.fromkeys(_FUNCTIONS.findall(live))),
        "direct_returns": len(_DIRECT_RETURN.findall(live)),
        "proxy_returns": len(live_proxy),
        "proxy_targets": tuple(dict.fromkeys(live_proxy)),
        "host_patterns": live_hosts,
        "subnets": live_subnets,
        "forwarding_targets": tuple(targets),
        # Unsubstituted ${...} gateway placeholders. Present in an authored
        # template; absent from the PAC a client was actually served.
        "unresolved_variables": unresolved,
        "is_template": bool(unresolved),
        "commented_host_patterns": tuple(
            host for host in all_hosts if host not in live_host_set
        ),
        "commented_proxy_targets": tuple(
            dict.fromkeys(value for value in all_proxy if value not in live_proxy_set)
        ),
        "commented_direct_returns": max(
            len(_DIRECT_RETURN.findall(text)) - len(_DIRECT_RETURN.findall(live)), 0
        ),
    }


def bypass_host_patterns(document: PacDocument, limit: int = 0) -> Sequence[str]:
    """Host patterns named in the PAC's *live* matching calls."""
    patterns = describe(document)["host_patterns"]
    return patterns[:limit] if limit else patterns
