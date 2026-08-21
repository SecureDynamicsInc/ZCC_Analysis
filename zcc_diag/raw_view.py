"""Raw log viewer — Slice 7 of the Log-Analyzer rebuild (2026-08-07).

Pure library. Takes a `LogIndex` and a `source_file` basename, yields
the parsed `IndexedLine` records for that file, paginated, with an
optional substring/regex filter and inline HTML syntax highlighting
of well-known tokens.

Design contract:
    * We read from the already-parsed LogIndex — no second pass over
      the raw log files. If a line was rejected by the parser (bad
      timestamp, malformed level), it's not in the index and won't
      appear here. That's a feature: the Raw view shows what the
      analyzer actually sees.
    * Highlighting is HTML with rigid regex-driven span wrappers. No
      LLM, no interpretation. What's highlighted is a token that
      matches a documented pattern (err_code, symbolic code, log
      level, ISO timestamp).
    * Text is escaped before highlighting so a malicious log line
      can't inject scripts.

Pure library — no streamlit deps. CLI-shared.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from zcc_diag.error_catalog import match_known_codes
from zcc_diag.synthetic_ip import describe_address


# --------------------------------------------------------------------------
# Highlight tokens
# --------------------------------------------------------------------------

# Note ordering matters — the highlighter applies them in this order,
# and the first pattern to claim a span wins. Longest/most-specific first.
_HIGHLIGHTS: List[Tuple[str, "re.Pattern"]] = [
    # ISO timestamp
    ("ts",
     re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
                r"(?:Z|[+-]\d{4}|[+-]\d{2}:\d{2})?\b")),
    # Symbolic ZS codes
    ("symcode",
     re.compile(
         r"\b(?:BRK_MT_[A-Z0-9_]{4,}|BRK_REDIRECT_[A-Z0-9_]+"
         r"|ZPN_[A-Z0-9_]{4,}|ZEVENT_[A-Z0-9_]{4,}|ZS_[A-Z0-9_]{4,})\b"
     )),
    # tag_id=NNN
    ("tagid", re.compile(r"\btag_id\s*[=:]\s*(\d+)\b", re.IGNORECASE)),
    # err_code=NNN
    ("errcode", re.compile(r"\berr[_ ]?code\s*[=:]\s*(\d+)\b", re.IGNORECASE)),
    # session_id / mtunnel_id / conn_id -- token+value
    ("idkv",
     re.compile(
         r"\b(?:session_id|mtunnel_id|conn_id)\s*[=:]\s*"
         r"([a-zA-Z0-9+/=_,\-]+)\b",
         re.IGNORECASE,
     )),
    # Broker hosts
    ("broker",
     re.compile(
         r"\bbroker[a-z0-9_-]*\.(?:[a-z0-9_-]+\.)*"
         r"(?:zpath|zscaler|zpalb|zpaservice)\.net\b",
         re.IGNORECASE,
     )),
    # Log level tokens (short form only — INF/WRN/ERR/DBG/TRC/VRB/FTL)
    ("level",
     re.compile(r"\b(?:INF|WRN|ERR|DBG|TRC|VRB|FTL|INFO|WARN|ERROR|"
                r"DEBUG|TRACE|VERBOSE|FATAL|CRIT|CRITICAL)\b")),
    # IPv4
    ("ipv4",
     re.compile(r"\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
                r"(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b")),
]


# CSS classes: caller can style however they want.
_TOKEN_CLS = {
    "ts":      "hl-ts",
    "symcode": "hl-symcode",
    "tagid":   "hl-tagid",
    "errcode": "hl-errcode",
    "idkv":    "hl-idkv",
    "broker":  "hl-broker",
    "level":   "hl-level",
    "ipv4":    "hl-ipv4",
}

# Default styles the UI drops into a <style> block.
#
# Dark-first, because the app's own default is dark and the previous palette was
# built for a light background — #005cc5 timestamps and #032f62 broker hosts on
# a near-black panel were effectively unreadable. Light mode overrides sit at the
# bottom, selected by a `la-raw-light` class the renderer adds.
#
# Severity is expressed as a left border plus a low-alpha row wash rather than
# by recolouring the text: the token colours still have to carry timestamp,
# code, and address meaning inside a red row.
DEFAULT_CSS = """
<style>
/* Typography and colour live on `.la-raw` itself, not on a `pre` selector.
 * Streamlit rewrites a `<pre>` inside unsafe HTML into
 * `<div data-testid="stMarkdownPre">`, so `.la-raw pre { ... }` matches
 * nothing — which is why this block used to inherit the theme's text colour
 * and turned unreadable in light mode. Both selectors are kept for the
 * whitespace rules so the view survives either markup. */
.la-raw {
    border: 1px solid rgba(148, 163, 184, .18); border-radius: 10px;
    background: #10182A; padding: 6px 0; overflow-x: auto;
    font-family: ui-monospace, "SF Mono", Consolas, monospace;
    font-size: 12.5px; line-height: 1.45; color: #C9D6E4;
}
.la-raw pre, .la-raw [data-testid="stMarkdownPre"] {
    margin: 0; background: transparent; color: inherit;
    font: inherit; white-space: pre; tab-size: 4; padding: 0;
    /* Explicit content width, in character columns, set inline by the
     * renderer from the widest record it is about to draw. `max-content`
     * cannot be used here: with content-visibility on the rows, the rows the
     * browser has skipped contribute only their intrinsic size, so
     * max-content collapses to the width of whatever is on screen and the
     * horizontal scrollbar never covers the real lines. */
    width: calc(var(--la-cols, 220) * 1ch);
    min-width: 100%;
}
.la-raw.la-raw-wrap pre,
.la-raw.la-raw-wrap [data-testid="stMarkdownPre"] {
    white-space: pre-wrap; word-break: break-all;
}
.la-raw .row {
    display: block; padding: 0 10px 0 0; border-left: 3px solid transparent;
    /* 100% of the pre's explicit width, so the row background reaches the end
     * of the longest line rather than stopping at the viewport edge. */
    min-width: 100%; box-sizing: border-box;
}
.la-raw .ln {
    color: #5C6C80; padding: 0 10px 0 6px; user-select: none;
    display: inline-block; min-width: 7ch; text-align: right;
    border-right: 1px solid rgba(148, 163, 184, .12); margin-right: 9px;
}
.la-raw .current { background: rgba(255, 214, 0, .18); }
.la-raw .match { background: rgba(79, 163, 227, .28); border-radius: 2px; }

/* Severity: critical red, medium orange, at high contrast across the whole
 * line. The wash is strong enough to find while scrolling fast, and the row's
 * own text colour is raised rather than left to inherit, because an ERR line
 * that is merely tinted is easy to scroll past. Token colours inside a flagged
 * row are brightened to stay legible against the wash instead of being
 * discarded — the address and the code on a failing line are the point. */
.la-raw .sev-critical {
    border-left-color: #FF5A5A; background: rgba(239, 68, 68, .22);
    color: #FFE1E1; font-weight: 600;
}
.la-raw .sev-medium {
    border-left-color: #FFB020; background: rgba(245, 158, 11, .20);
    color: #FFEBC7; font-weight: 600;
}
.la-raw .sev-critical .ln { color: #FFB4B4; }
.la-raw .sev-medium .ln   { color: #FFD79A; }
.la-raw .sev-critical .hl-ts, .la-raw .sev-medium .hl-ts { color: #BBD6F5; }
.la-raw .sev-critical .hl-ipv4, .la-raw .sev-medium .hl-ipv4 { color: #C7F0C9; }
.la-raw .sev-critical .hl-broker, .la-raw .sev-medium .hl-broker { color: #AFD9FF; }
.la-raw .sev-critical .hl-tagid, .la-raw .sev-medium .hl-tagid { color: #B6EFCB; }
.la-raw .sev-critical .hl-idkv, .la-raw .sev-medium .hl-idkv { color: #DCC9FF; }
.la-raw .sev-critical .hl-level, .la-raw .sev-medium .hl-level { color: #FFE08A; }
.la-raw .sev-critical .hl-errcode, .la-raw .sev-critical .hl-symcode { color: #FFC9C4; }
.la-raw .sev-medium .hl-errcode, .la-raw .sev-medium .hl-symcode { color: #FFD9B0; }

/* A synthetic address is marked as fabricated rather than left looking like a
 * destination: dotted underline, and a hover note saying what the range is. */
.la-raw .hl-synthetic {
    text-decoration: underline dotted;
    text-underline-offset: 2px;
    cursor: help;
}

/* The level column is colour-coded per level, so a log can be scanned by level
 * without reading the text. ERR/CRT and WAR/WRN match the row severity
 * colours; the quieter levels stay quiet. */
.la-raw .lv { display: inline-block; min-width: 4ch; font-weight: 700; }
.la-raw .lv-err, .la-raw .lv-crt { color: #FF6B6B; }
.la-raw .lv-war, .la-raw .lv-wrn { color: #FFB020; }
.la-raw .lv-inf { color: #7FB2E5; }
.la-raw .lv-dbg { color: #7C8CA1; font-weight: 600; }
.la-raw .lv-trc { color: #6E7F94; font-weight: 600; font-style: italic; }
.la-raw .sev-critical .lv-err, .la-raw .sev-critical .lv-crt { color: #FFD5D5; }
.la-raw .sev-medium .lv-war, .la-raw .sev-medium .lv-wrn { color: #FFE7BF; }

.la-raw .hl-ts       { color: #6BA8DC; }
.la-raw .hl-symcode  { color: #E58AC8; font-weight: 600; }
.la-raw .hl-tagid    { color: #7FD1A0; }
.la-raw .hl-errcode  { color: #FF7B72; font-weight: 600; }
.la-raw .hl-idkv     { color: #C0A6E8; }
.la-raw .hl-broker   { color: #79C0FF; text-decoration: underline; }
.la-raw .hl-level    { color: #E3B341; }
.la-raw .hl-ipv4     { color: #A5D6A7; }

.la-raw-legend { display: flex; gap: 14px; align-items: center; margin: 2px 0 8px; }
.la-raw-legend span { color: #93A4B8; font-size: 11px; display: flex; align-items: center; gap: 5px; }
.la-raw-legend i { width: 9px; height: 9px; border-radius: 2px; display: inline-block; }
.la-raw-legend .k-critical { background: #EF4444; }
.la-raw-legend .k-medium { background: #F59E0B; }
.la-raw-legend .k-other { background: #475569; }

/* Light mode. The app has no `data-theme` hook — `inject_css` simply appends a
 * light stylesheet — so the container carries `la-raw-light`, set from the same
 * `light_mode` session flag the theme itself reads. Colours are !important
 * because the light theme sets the markdown container's colour that way. */
.la-raw.la-raw-light {
    background: #FFFFFF; border-color: rgba(40, 61, 82, .18); color: #24292F !important;
}
.la-raw-light .ln { color: #8A94A0 !important; border-right-color: rgba(40, 61, 82, .12); }
.la-raw-light .lv-err, .la-raw-light .lv-crt { color: #B3261E !important; }
.la-raw-light .lv-war, .la-raw-light .lv-wrn { color: #8A5300 !important; }
.la-raw-light .lv-inf { color: #10508A !important; }
.la-raw-light .lv-dbg { color: #6A7684 !important; }
.la-raw-light .lv-trc { color: #78838F !important; font-style: italic; }
.la-raw-light .sev-critical .lv-err, .la-raw-light .sev-critical .lv-crt { color: #6E0B12 !important; }
.la-raw-light .sev-medium .lv-war, .la-raw-light .sev-medium .lv-wrn { color: #5A3B00 !important; }
.la-raw-light .hl-ts       { color: #005CC5 !important; }
.la-raw-light .hl-symcode  { color: #A71D5D !important; }
.la-raw-light .hl-tagid    { color: #22863A !important; }
.la-raw-light .hl-errcode  { color: #D73A49 !important; }
.la-raw-light .hl-idkv     { color: #6F42C1 !important; }
.la-raw-light .hl-broker   { color: #032F62 !important; }
.la-raw-light .hl-level    { color: #B08800 !important; }
.la-raw-light .hl-ipv4     { color: #6F42C1 !important; }
.la-raw-light .sev-critical {
    background: #FCE3E5; border-left-color: #C62828;
    color: #6E0B12 !important; font-weight: 600;
}
.la-raw-light .sev-medium {
    background: #FDF0D5; border-left-color: #B26A00;
    color: #5A3B00 !important; font-weight: 600;
}
.la-raw-light .sev-critical .ln { color: #A3323A !important; }
.la-raw-light .sev-medium .ln   { color: #8A6100 !important; }
.la-raw-light .sev-critical .hl-ts, .la-raw-light .sev-medium .hl-ts { color: #12457F !important; }
.la-raw-light .sev-critical .hl-ipv4, .la-raw-light .sev-medium .hl-ipv4 { color: #14602A !important; }
.la-raw-light .sev-critical .hl-broker, .la-raw-light .sev-medium .hl-broker { color: #123C6B !important; }
.la-raw-light .sev-critical .hl-tagid, .la-raw-light .sev-medium .hl-tagid { color: #14602A !important; }
.la-raw-light .sev-critical .hl-idkv, .la-raw-light .sev-medium .hl-idkv { color: #4B2A8A !important; }
.la-raw-light .sev-critical .hl-level, .la-raw-light .sev-medium .hl-level { color: #7A4B00 !important; }
.la-raw-light .sev-critical .hl-errcode, .la-raw-light .sev-critical .hl-symcode { color: #8C1119 !important; }
.la-raw-light .sev-medium .hl-errcode, .la-raw-light .sev-medium .hl-symcode { color: #7A3E00 !important; }
.la-raw-light .match { background: rgba(33, 110, 166, .20); }
</style>
"""


# --------------------------------------------------------------------------
# Highlighter
# --------------------------------------------------------------------------

def highlight_tokens(body: str) -> str:
    """Return HTML-safe body text with well-known tokens wrapped in
    `<span class="hl-...">` markers.

    The function tokenises a single line at a time. Non-overlapping
    match spans are chosen greedily in the order defined by `_HIGHLIGHTS`.
    """
    if not body:
        return ""

    # Collect (start, end, cls_name) matches. Earlier pattern wins on overlap.
    n = len(body)
    claimed = bytearray(n)  # 0 = unclaimed, 1 = claimed
    spans: List[Tuple[int, int, str]] = []

    for token_name, pat in _HIGHLIGHTS:
        cls = _TOKEN_CLS[token_name]
        for m in pat.finditer(body):
            s, e = m.start(), m.end()
            if any(claimed[s:e]):
                continue
            for i in range(s, e):
                claimed[i] = 1
            spans.append((s, e, cls))

    if not spans:
        return html.escape(body)

    spans.sort()
    out_parts: List[str] = []
    cursor = 0
    for s, e, cls in spans:
        if s > cursor:
            out_parts.append(html.escape(body[cursor:s]))
        token = body[s:e]
        note = describe_address(token) if cls == "hl-ipv4" else None
        if note is not None:
            # A 100.64.x.x address is fabricated by the client, so say what it is
            # where the reader meets it rather than in documentation they would
            # have to go and find.
            out_parts.append(
                f'<span class="{cls} hl-synthetic" title="{html.escape(note.title)}">'
                f'{html.escape(token)}</span>'
            )
        else:
            out_parts.append(
                f'<span class="{cls}">{html.escape(token)}</span>'
            )
        cursor = e
    if cursor < n:
        out_parts.append(html.escape(body[cursor:]))
    return "".join(out_parts)


# --------------------------------------------------------------------------
# File-scoped iteration
# --------------------------------------------------------------------------

@dataclass
class RawLine:
    """One line as rendered by the Raw view."""
    line_no: int
    ts_iso: str
    level: str
    body: str
    highlighted: str  # HTML-safe body with syntax highlighting
    severity: str = ""       # "critical" | "medium" | ""
    severity_why: str = ""   # what earned the severity, for the row title


def list_source_files(idx) -> List[Tuple[str, int]]:
    """Return `[(source_file, line_count), ...]` sorted by filename."""
    counts = {}
    for ln in idx.lines:
        if ln.source_file:
            counts[ln.source_file] = counts.get(ln.source_file, 0) + 1
    return sorted(counts.items())


def get_file_lines(idx,
                   source_file: str,
                   substring: Optional[str] = None,
                   regex: Optional[str] = None) -> List:
    """Return every IndexedLine belonging to `source_file`, optionally
    filtered by a substring or regex against the body.

    Kept as a plain function so the caller can further slice via
    Python's list operations. We don't paginate here — that's the
    UI's job.
    """
    q_pat = None
    if regex:
        try:
            q_pat = re.compile(regex, re.IGNORECASE)
        except re.error:
            q_pat = None

    q_lower = substring.lower() if substring else None

    out = []
    for ln in idx.lines:
        if ln.source_file != source_file:
            continue
        if q_lower is not None and q_lower not in (ln.body or "").lower():
            continue
        if q_pat is not None and not q_pat.search(ln.body or ""):
            continue
        out.append(ln)
    return out


def paginate(lines: List, page: int, page_size: int
             ) -> Tuple[List, int, int]:
    """Given all lines, return the slice for the requested page.

    Returns (slice, page, total_pages). Pages are 1-based. Out-of-range
    pages are clamped.
    """
    if page_size <= 0:
        page_size = 200
    n = len(lines)
    total_pages = max(1, (n + page_size - 1) // page_size)
    if page < 1:
        page = 1
    if page > total_pages:
        page = total_pages
    start = (page - 1) * page_size
    end = start + page_size
    return (lines[start:end], page, total_pages)


# --------------------------------------------------------------------------
# Per-line severity
#
# Two signals, and the stronger wins:
#
#   The documented catalog. `match_known_codes` resolves a line against the
#   749 bundled ZCC/ZIA/ZPA/ZDX entries, 310 of which are documented critical
#   and 360 warning. This is the authority on impact, so a documented critical
#   code colours the row even when the record's own level is INFO — which is
#   exactly how several terminal tunnel states are logged.
#
#   The record's level. ERROR / FATAL / CRITICAL is critical, WARN is medium.
#   This catches real failures that carry no documented code.
#
# Cost: measured at 0.20 s for 50,000 lines, so it runs on the whole page
# rather than being sampled or deferred.
# --------------------------------------------------------------------------

SEVERITY_CRITICAL = "critical"
SEVERITY_MEDIUM = "medium"

# The store's own line regex captures the level as one of
# DBG|INF|WAR|WRN|ERR|CRT|TRC and stores it unnormalised, so the three-letter
# forms are what actually appear. `WAR` and `CRT` were missing from these sets,
# which meant the most common warning spelling in a real ZCC log was never
# coloured at all. Long forms are kept for logs that use them.
ERROR_LEVELS = frozenset({"ERR", "CRT", "ERROR", "CRITICAL", "CRIT", "FATAL", "FTL"})
WARNING_LEVELS = frozenset({"WAR", "WRN", "WARN", "WARNING"})

_CRITICAL_LEVELS = ERROR_LEVELS
_MEDIUM_LEVELS = WARNING_LEVELS

#: Level-filter scopes offered by the viewers.
LEVEL_SCOPE_ALL = "All records"
LEVEL_SCOPE_BOTH = "ERR + WAR"
LEVEL_SCOPE_ERRORS = "ERR only"
LEVEL_SCOPE_WARNINGS = "WAR only"
LEVEL_SCOPES = (
    LEVEL_SCOPE_ALL, LEVEL_SCOPE_BOTH, LEVEL_SCOPE_ERRORS, LEVEL_SCOPE_WARNINGS,
)
_SEVERITY_RANK = {"": 0, SEVERITY_MEDIUM: 1, SEVERITY_CRITICAL: 2}


def line_severity(level: str, body: str) -> Tuple[str, str]:
    """Return ``(severity, why)`` for one record.

    ``severity`` is ``"critical"``, ``"medium"``, or ``""``. ``why`` names what
    earned it, so the UI can show the reason rather than an unexplained colour.
    """
    documented = ""
    documented_why = ""
    matches = match_known_codes(body or "")
    if matches:
        severities = {entry.severity for entry in matches}
        if "critical" in severities:
            documented = SEVERITY_CRITICAL
        elif "warning" in severities:
            documented = SEVERITY_MEDIUM
        if documented:
            named = next(
                (entry for entry in matches
                 if entry.severity == ("critical" if documented == SEVERITY_CRITICAL else "warning")),
                None,
            )
            label = (named.code or named.label) if named else ""
            documented_why = (
                f"documented {'critical' if documented == SEVERITY_CRITICAL else 'warning'}"
                + (f": {label}" if label else "")
            )

    upper = (level or "").upper()
    from_level = (
        SEVERITY_CRITICAL if upper in _CRITICAL_LEVELS
        else SEVERITY_MEDIUM if upper in _MEDIUM_LEVELS
        else ""
    )

    if _SEVERITY_RANK[documented] >= _SEVERITY_RANK[from_level] and documented:
        return documented, documented_why
    if from_level:
        return from_level, f"{upper} record"
    return "", ""


#: Gutter + timestamp + level + separators, in character columns, ahead of the
#: record body. Kept next to the renderer that lays them out.
_PREFIX_COLUMNS = 7 + 3 + 19 + 2 + 5 + 2


def level_html(level: str) -> str:
    """The level cell, class-tagged so CSS can colour it per level."""
    text = (level or "")
    slug = text.strip().lower()[:3]
    known = {"err", "crt", "war", "wrn", "inf", "dbg", "trc"}
    cls = f"lv lv-{slug}" if slug in known else "lv"
    return f'<span class="{cls}">{html.escape(text):<5}</span>'


def content_columns(lines: Sequence[RawLine], *, minimum: int = 120) -> int:
    """Width in character columns needed to show the longest record in full.

    The rendered block needs an explicit width because `content-visibility`
    hides the skipped rows' real width from the scroller, so `max-content`
    collapses to whatever is on screen and horizontal scrolling stops short of
    the long lines. Measuring here — where the records are already in hand — is
    exact for a monospace font, since one column is one `ch`.
    """
    longest = max((len(line.body) for line in lines), default=0)
    return max(minimum, longest + _PREFIX_COLUMNS)


def filter_by_level(lines: Sequence[RawLine], scope: str) -> List[RawLine]:
    """Filter records by their log level, keeping original line numbers.

    Level-based rather than severity-based on purpose: this answers "show me the
    ERR and WAR records", which is a question about what the client logged, not
    about what the catalog considers impactful.
    """
    wanted = {
        LEVEL_SCOPE_ERRORS: ERROR_LEVELS,
        LEVEL_SCOPE_WARNINGS: WARNING_LEVELS,
        LEVEL_SCOPE_BOTH: ERROR_LEVELS | WARNING_LEVELS,
    }.get(scope)
    if not wanted:
        return list(lines)
    return [line for line in lines if (line.level or "").upper() in wanted]


def severity_counts(lines: Sequence[RawLine]) -> Dict[str, int]:
    """Tally of critical / medium / other across the given lines."""
    counts = {SEVERITY_CRITICAL: 0, SEVERITY_MEDIUM: 0, "other": 0}
    for line in lines:
        counts[line.severity or "other"] = counts.get(line.severity or "other", 0) + 1
    return counts


def to_raw_lines(indexed_lines) -> List[RawLine]:
    """Convert IndexedLine records into RawLine records with pre-rendered
    highlighted HTML. Called by the UI to save its rerun budget."""
    out: List[RawLine] = []
    for ln in indexed_lines:
        ts_iso = ln.ts.strftime("%Y-%m-%d %H:%M:%S") if ln.ts else "-"
        body = ln.body or ""
        severity, why = line_severity(ln.level or "", body)
        out.append(RawLine(
            line_no=ln.line_no,
            ts_iso=ts_iso,
            level=ln.level or "",
            body=body,
            highlighted=highlight_tokens(body),
            severity=severity,
            severity_why=why,
        ))
    return out


def find_line_index(lines, target_line_no: int) -> Optional[int]:
    """Return the index in `lines` whose `line_no == target_line_no`.
    Binary-search-friendly but we keep it linear because file line
    counts are moderate (bundles ~= tens of thousands of lines per
    file)."""
    for i, ln in enumerate(lines):
        if ln.line_no == target_line_no:
            return i
    return None
